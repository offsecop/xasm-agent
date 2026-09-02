"""Bounded URL-only information-disclosure probe (#1287).

The tool is a safe front door for the disclosure skill.  It accepts a root URL,
discovers a small same-origin surface, validates concrete disclosure markers,
and returns Nuclei-shaped findings with sanitized HTTP transcripts.  Raw secret
values never leave this process; an optional PortSwigger-style solution submit
uses the value in memory and is gated by server-owned lab flags.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import secrets
from html.parser import HTMLParser
from typing import Any, ClassVar, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp

from plugin_interface import ToolPlugin


MODE = "bounded-root-disclosure-v1"
RUNTIME_PROOF = "runtime-read-only"
LAB_PROOF = "lab-state-change"
USER_AGENT = "xASM-information-disclosure-probe/1.0"

UNSAFE_PATH_RE = re.compile(
    r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|destroy|remove|checkout|purchase|"
    r"transfer|withdraw|redeem|unsubscribe)(?:/|$)",
    re.I,
)
HTML_RE = re.compile(r"(?is)<(?:!doctype|html|head|body|title)\b")
INDEX_RE = re.compile(r"(?is)<title>\s*Index of\s+[^<]+</title>|<h1>\s*Index of\s+[^<]+</h1>")
AUTOINDEX_RE = re.compile(
    r"(?is)<title>\s*Index of\s+/[^<]*</title>|<h1>\s*Index of\s+/[^<]*</h1>"
)
SOURCE_MAP_RE = re.compile(r"(?://[#@]\s*sourceMappingURL\s*=\s*([^\s*]+))", re.I)
COMMENT_RE = re.compile(r"(?is)<!--(.*?)-->")
GIT_HEAD_RE = re.compile(r"^ref:\s+refs/heads/[A-Za-z0-9._/-]+\s*$", re.I)
VERSION_PATTERNS = [
    re.compile(r"\bApache\s+Struts(?:\s+2)?\s+(\d+\.\d+(?:\.\d+){1,2})\b", re.I),
    re.compile(r"\b(?:Spring Framework|Django|Flask|Werkzeug|Laravel|Ruby on Rails)"
               r"[/\s-]+v?(\d+\.\d+(?:\.\d+){0,2})\b", re.I),
]
STACK_MARKERS = (
    "java.lang.",
    "at com.",
    "traceback (most recent call last)",
    "stack trace",
    "system.nullreferenceexception",
    "org.apache.struts",
    "sqlstate[",
    "syntax error at or near",
    "unterminated quoted string",
)
DEBUG_MARKERS = (
    "php version",
    "phpinfo()",
    "configuration file (php.ini) path",
    "environment variables",
    "request_method",
    "spring boot actuator",
    "active profiles",
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(secret[_-]?key|app[_-]?key|db[_-]?password|database[_-]?password|"
    r"api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\b"
    r"\s*(?:[:=]|\s)\s*['\"]?([A-Za-z0-9_+/.=@!#$%^&*()\-]{8,})"
)
CONNECTION_SECRET_RE = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s'\"<]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
SENSITIVE_QUERY_VALUE_RE = re.compile(
    r"(?i)((?:\?|&(?:amp;|#0*38;|#x0*26;)?)(?:x-(?:amz|goog)-"
    r"(?:signature|credential|security-token)|googleaccessid|awsaccesskeyid|"
    r"signature|sig|secret|passw(?:or)?d|token|api[_-]?key|auth|session|csrf|xsrf)="
    r")([^&#\"'\s<>]+)"
)
SOURCE_MARKERS = (
    "<?php",
    "public class ",
    "private class ",
    "connectionbuilder.from(",
    "def ",
    "import ",
    "package ",
    "require(",
    "module.exports",
)
BACKUP_SUFFIXES = (".bak", ".old", ".orig", ".save", ".swp", "~")
DEBUG_PATHS = (
    "/cgi-bin/phpinfo.php",
    "/phpinfo.php",
    "/info.php",
    "/debug",
    "/actuator/env",
    "/server-status",
)
TRUSTED_HEADER_NAMES = {
    "x-custom-ip-authorization",
    "x-internal-user",
    "x-authenticated-user",
    "x-original-client-ip",
}
SENSITIVE_HEADER_RE = re.compile(
    r"(?i)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|"
    r"x-csrf-token|x-xsrf-token)$"
)
COOKIE_PAIR_RE = re.compile(
    r"(?i)\b(?:session(?:id)?|phpsessid|jsessionid|connect\.sid|auth(?:entication)?|"
    r"access[_-]?token|refresh[_-]?token)\s*=\s*"
    r"([A-Za-z0-9_+/.@%~-]{8,})"
)
COOKIE_TABLE_VALUE_RE = re.compile(
    r"(?i)(?:\$_COOKIE\s*\[\s*['\"][^'\"]+['\"]\s*\]|HTTP_COOKIE)\s+"
    r"([A-Za-z0-9_+/.@%~-]{8,})"
)


class HttpObservation:
    def __init__(
        self,
        method: str,
        url: str,
        status: Optional[int],
        request_headers: Dict[str, str],
        response_headers: Dict[str, str],
        body: str,
    ) -> None:
        self.method = method
        self.url = url
        self.status = status
        self.request_headers = request_headers
        self.response_headers = response_headers
        self.body = body


class _DiscoveryParser(HTMLParser):
    URL_ATTRS: ClassVar[set[str]] = {"href", "src", "action", "data-src"}
    COMMENT_URL_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:href|src|action|data-src)\s*=\s*"
        r"(?:\"([^\"]+)\"|'([^']+)'|([^\s>]+))"
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: List[str] = []

    def handle_starttag(self, _tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        for name, value in attrs:
            if str(name or "").lower() in self.URL_ATTRS and value:
                self.urls.append(str(value).strip())

    def handle_comment(self, data: str) -> None:
        # Diagnostic links are frequently commented out instead of removed
        # from production markup. Discover only explicit URL-bearing
        # attributes; never treat arbitrary comment text as a path candidate.
        for match in self.COMMENT_URL_RE.finditer(data):
            value = next((group for group in match.groups() if group), None)
            if value:
                self.urls.append(value.strip())


class _AutoindexEntryParser(HTMLParser):
    """Collect only navigable anchors from a server-generated index."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if str(tag or "").lower() != "a":
            return
        for name, value in attrs:
            if str(name or "").lower() == "href" and value:
                self.urls.append(str(value).strip())
                return


class WebInformationDisclosureProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:information_disclosure_probe"

    @property
    def description(self) -> str:
        return (
            "Discovers and confirms bounded same-origin information disclosure from a root URL: "
            "verbose errors, debug secrets, robots-to-backup source, exposed Git indicators, "
            "source maps, and reflected trusted headers. Returns sanitized Request/Response proof."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "format": "uri"},
                "mode": {"type": "string", "enum": [MODE], "default": MODE},
                "proofLevel": {
                    "type": "string",
                    "enum": [RUNTIME_PROOF, LAB_PROOF],
                    "default": RUNTIME_PROOF,
                },
                "engagement": {
                    "type": "string",
                    "enum": ["standard", "aggressive", "lab", "ctf"],
                    "default": "standard",
                },
                "discoverFromTarget": {"type": "boolean", "default": True},
                "maxDiscoveryPages": {
                    "type": "integer", "default": 5, "minimum": 1, "maximum": 12,
                },
                "requestBudget": {
                    "type": "integer", "default": 32, "minimum": 8, "maximum": 80,
                },
                "maxResponseBytes": {
                    "type": "integer", "default": 250000, "minimum": 4096, "maximum": 1000000,
                },
                "stopAfterFirstFinding": {"type": "boolean", "default": True},
                # These booleans are overwritten by backend policy. There is no
                # public answer/path/payload/marker/header/cookie input.
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "solutionSubmitApproved": {"type": "boolean", "default": False},
            },
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "dast",
            "phase": 2,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["browser:", "katana:", "dirsearch:"],
            "chainable_before": ["git:source_disclosure_scanner", "decision:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        target = self._origin(parameters.get("target"))
        if not target:
            return self._error("target must be an absolute http(s) URL")
        if str(parameters.get("mode") or MODE) != MODE:
            return self._error(f"unsupported mode; expected {MODE}")

        proof_level = (
            LAB_PROOF if str(parameters.get("proofLevel") or "").lower() == LAB_PROOF
            else RUNTIME_PROOF
        )
        engagement = str(parameters.get("engagement") or "standard").lower()
        self._max_pages = self._bounded_int(parameters.get("maxDiscoveryPages"), 5, 1, 12)
        self._budget = self._bounded_int(parameters.get("requestBudget"), 32, 8, 80)
        self._max_bytes = self._bounded_int(parameters.get("maxResponseBytes"), 250000, 4096, 1000000)
        self._stop_first = bool(parameters.get("stopAfterFirstFinding", True))
        self._requests = 0
        self._bytes = 0
        self._observations: Dict[str, HttpObservation] = {}
        self._private_values: List[str] = []

        # Auth material is intentionally not in the public schema. The runtime
        # may inject these private keys after policy/scope validation.
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        for source_key in ("authHeaders", "headers"):
            extra = parameters.get(source_key)
            if isinstance(extra, dict):
                headers.update({str(k): str(v) for k, v in extra.items()})
                self._private_values.extend(str(v) for v in extra.values() if str(v))
        cookie = parameters.get("authCookies") or parameters.get("cookie")
        if cookie:
            headers["Cookie"] = str(cookie)
            self._private_values.append(str(cookie))

        timeout = aiohttp.ClientTimeout(total=20)
        connector = aiohttp.TCPConnector(limit=6)  # TLS verification remains enabled.
        async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector) as session:
            self._session = session
            root = await self._request("GET", target + "/")
            if root.status is None:
                return self._error("target was unreachable", target=target)
            negative_token = secrets.token_hex(12)
            negative = await self._request("GET", f"{target}/.xasm-not-found-{negative_token}")
            negative_hash = self._body_hash(negative.body)

            candidates: List[Tuple[Dict[str, Any], HttpObservation, Optional[str]]] = []
            directory_listing = self._classify_directory_listing(root, target, negative_hash)
            if directory_listing:
                candidates.append((directory_listing, root, None))

            # A confirmed root autoindex is already sufficient evidence. Avoid
            # downloading every listed file just to rediscover the same leak.
            if candidates and self._stop_first:
                page_urls = [target + "/"]
                all_urls = [target + "/"]
                bodies = {target + "/": root.body}
            else:
                page_urls, all_urls, bodies = await self._discover(target, root)

            # Observed pages first: debug links and typed query parameters.
            for url in (all_urls if not candidates else []):
                path = urlparse(url).path.lower()
                if any(token in path for token in ("debug", "phpinfo", "actuator", "server-status")):
                    obs = await self._cached_get(url)
                    hit = self._classify_debug(obs, negative_hash)
                    if hit:
                        candidates.append((hit, obs, hit.pop("_rawValue", None)))
                        if self._stop_first:
                            break
            if not candidates:
                candidates.extend(await self._probe_verbose_errors(all_urls, negative_hash))

            # Robots/sitemap and fixed read-only indicators are still bounded by
            # the same global request counter.
            robots_paths: List[str] = []
            if not candidates:
                robots = await self._request("GET", target + "/robots.txt")
                if robots.status == 200 and self._body_hash(robots.body) != negative_hash:
                    robots_paths = self._robots_paths(robots.body, target)
            if not candidates:
                candidates.extend(await self._probe_backups(robots_paths, all_urls, negative_hash))
            if not candidates:
                candidates.extend(await self._probe_debug_paths(target, negative_hash))
            if not candidates:
                git = await self._request("GET", target + "/.git/HEAD")
                if git.status == 200 and GIT_HEAD_RE.match(git.body.strip()) and self._body_hash(git.body) != negative_hash:
                    candidates.append(({
                        "kind": "vcs_exposure",
                        "title": "Exposed Git Repository Metadata",
                        "severity": "medium",
                        "marker": git.body.strip()[:160],
                        "description": "The web root exposes a content-validated .git/HEAD file.",
                        "remediation": "Remove VCS metadata from deployments and deny dot-directory access.",
                    }, git, None))
            if not candidates:
                candidates.extend(await self._probe_source_maps(target, bodies, negative_hash))
            if not candidates:
                trace_hit = await self._probe_trace(target, negative_hash)
                if trace_hit:
                    candidates.append(trace_hit)

            findings: List[Dict[str, Any]] = []
            verification: Dict[str, Any] = {
                "verified": False,
                "mode": MODE,
                "proofLevel": proof_level,
                "requestCount": self._requests,
                "bytesRead": self._bytes,
                "discoveryPages": len(page_urls),
                "discoveredUrls": len(all_urls),
                "fallback": False,
            }

            if candidates:
                hit, obs, raw_value = candidates[0]
                supporting = hit.pop("_supporting", [])
                transactions = [
                    *[
                        self._transaction(str(label), evidence_obs, raw_value)
                        for label, evidence_obs in supporting
                    ],
                    self._transaction("disclosure-proof", obs, raw_value),
                ]
                solution = await self._maybe_finalize_lab(
                    target=target,
                    root_before=root,
                    raw_value=raw_value,
                    proof_level=proof_level,
                    engagement=engagement,
                    approved=(
                        bool(parameters.get("allowUnsafeMethods"))
                        and bool(parameters.get("stateChangeApproved"))
                        and bool(parameters.get("solutionSubmitApproved"))
                    ),
                )
                transactions.extend(solution.pop("transactions", []))
                findings.append(self._finding(hit, obs, raw_value, transactions, solution))
                verification.update({
                    "verified": True,
                    "leakKind": hit["kind"],
                    "matchedUrl": obs.url,
                    "nonSecretMarker": hit.get("marker") if raw_value is None else None,
                    "disclosedValue": self._safe_value(hit["kind"], raw_value) if raw_value else None,
                    "httpEvidence": {"version": 1, "steps": transactions},
                    **solution,
                })

            verification["requestCount"] = self._requests
            verification["bytesRead"] = self._bytes
            return {
                "success": True,
                "tool": self.name,
                "target": target,
                "mode": MODE,
                "proofLevel": proof_level,
                "verified": bool(findings),
                "fallback": False,
                "findings": findings,
                "total_findings": len(findings),
                "verification": self._without_none(verification),
                "summary": {
                    "requestCount": self._requests,
                    "bytesRead": self._bytes,
                    "discoveryPages": len(page_urls),
                    "discoveredUrls": len(all_urls),
                    "findings": len(findings),
                    "fallback": False,
                },
            }

    async def _discover(
        self, target: str, root: HttpObservation,
    ) -> Tuple[List[str], List[str], Dict[str, str]]:
        queue = [target + "/"]
        pages: List[str] = []
        urls: List[str] = []
        bodies: Dict[str, str] = {}
        seen: set[str] = set()
        while queue and len(pages) < self._max_pages and self._requests < self._budget:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            obs = root if current == target + "/" else await self._cached_get(current)
            pages.append(current)
            bodies[current] = obs.body
            if obs.status != 200 or not self._is_html(obs):
                continue
            parser = _DiscoveryParser()
            try:
                parser.feed(obs.body)
            except Exception:
                pass
            for raw in parser.urls:
                absolute = self._safe_same_origin_url(target, current, raw)
                if not absolute or absolute in urls:
                    continue
                urls.append(absolute)
                parsed = urlparse(absolute)
                if (
                    parsed.query
                    or len(pages) >= self._max_pages
                    or self._skip_navigation(parsed.path)
                    or self._static_extension(parsed.path)
                ):
                    continue
                queue.append(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", "")))
        return pages, [target + "/", *urls], bodies

    async def _probe_verbose_errors(
        self, urls: Iterable[str], negative_hash: str,
    ) -> List[Tuple[Dict[str, Any], HttpObservation, Optional[str]]]:
        for url in urls:
            parsed = urlparse(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            for index, (name, value) in enumerate(pairs):
                if not re.fullmatch(r"-?\d+", value or ""):
                    continue
                baseline = await self._cached_get(url)
                mutated_pairs = list(pairs)
                mutated_pairs[index] = (name, "x")
                mutated = urlunparse(parsed._replace(query=urlencode(mutated_pairs)))
                attack = await self._request("GET", mutated)
                if self._body_hash(attack.body) == negative_hash:
                    continue
                hit = self._classify_verbose_error(baseline, attack)
                if not hit:
                    continue
                confirmation_pairs = list(pairs)
                confirmation_pairs[index] = (name, "xasm-invalid")
                confirmation_url = urlunparse(
                    parsed._replace(query=urlencode(confirmation_pairs)),
                )
                confirmation = await self._request("GET", confirmation_url)
                confirmation_hit = self._classify_verbose_error(baseline, confirmation)
                if (
                    confirmation_hit
                    and confirmation_hit.get("kind") == hit.get("kind")
                    and confirmation_hit.get("marker") == hit.get("marker")
                ):
                    hit["_supporting"] = [
                        ("clean-baseline", baseline),
                        ("stable-confirmation", confirmation),
                    ]
                    return [(hit, attack, None)]
        return []

    async def _probe_debug_paths(
        self, target: str, negative_hash: str,
    ) -> List[Tuple[Dict[str, Any], HttpObservation, Optional[str]]]:
        for path in DEBUG_PATHS:
            obs = await self._request("GET", target + path)
            hit = self._classify_debug(obs, negative_hash)
            if hit:
                return [(hit, obs, hit.pop("_rawValue", None))]
        return []

    async def _probe_backups(
        self, robots_paths: Iterable[str], observed_urls: Iterable[str], negative_hash: str,
    ) -> List[Tuple[Dict[str, Any], HttpObservation, Optional[str]]]:
        candidates: List[str] = []
        for url in [*robots_paths, *observed_urls]:
            path = urlparse(url).path
            if not path or self._skip_navigation(path):
                continue
            if path.endswith(BACKUP_SUFFIXES):
                candidates.append(url)
                continue
            if path.endswith("/") or "." not in path.rsplit("/", 1)[-1]:
                listing = await self._cached_get(url if path.endswith("/") else url + "/")
                if listing.status == 200 and INDEX_RE.search(listing.body):
                    parser = _DiscoveryParser()
                    try:
                        parser.feed(listing.body)
                    except Exception:
                        pass
                    for raw in parser.urls:
                        found = self._safe_same_origin_url(self._origin(url) or "", listing.url, raw)
                        if found and urlparse(found).path.endswith(BACKUP_SUFFIXES):
                            candidates.append(found)
            elif any(path.lower().endswith(ext) for ext in (".php", ".java", ".py", ".js", ".ts")):
                candidates.extend(url + suffix for suffix in BACKUP_SUFFIXES[:3])
        for url in self._dedupe(candidates)[:10]:
            obs = await self._cached_get(url)
            if obs.status != 200 or self._body_hash(obs.body) == negative_hash:
                continue
            hit = self._classify_source(obs)
            if hit:
                return [(hit, obs, hit.pop("_rawValue", None))]
        return []

    async def _probe_source_maps(
        self, target: str, bodies: Dict[str, str], negative_hash: str,
    ) -> List[Tuple[Dict[str, Any], HttpObservation, Optional[str]]]:
        map_urls: List[str] = []
        for page_url, body in bodies.items():
            for raw in SOURCE_MAP_RE.findall(body):
                candidate = self._safe_same_origin_url(target, page_url, raw.strip("'\""))
                if candidate:
                    map_urls.append(candidate)
            parser = _DiscoveryParser()
            try:
                parser.feed(body)
            except Exception:
                pass
            for raw in parser.urls:
                if raw.lower().endswith(".js"):
                    js_url = self._safe_same_origin_url(target, page_url, raw)
                    if not js_url:
                        continue
                    js = await self._cached_get(js_url)
                    for source_map in SOURCE_MAP_RE.findall(js.body):
                        candidate = self._safe_same_origin_url(target, js_url, source_map.strip("'\""))
                        if candidate:
                            map_urls.append(candidate)
        for url in self._dedupe(map_urls)[:5]:
            obs = await self._cached_get(url)
            if obs.status != 200 or self._body_hash(obs.body) == negative_hash:
                continue
            try:
                parsed = json.loads(obs.body)
            except Exception:
                continue
            sources = parsed.get("sources") if isinstance(parsed, dict) else None
            contents = parsed.get("sourcesContent") if isinstance(parsed, dict) else None
            if isinstance(sources, list) and sources and isinstance(contents, list) and any(contents):
                return [({
                    "kind": "source_map",
                    "title": "Production Source Map Exposes Original Source",
                    "severity": "low",
                    "marker": f"sources:{len(sources)}",
                    "description": "A publicly reachable source map embeds original application source.",
                    "remediation": "Do not publish source maps containing sourcesContent in production.",
                }, obs, None)]
        return []

    async def _probe_trace(
        self, target: str, negative_hash: str,
    ) -> Optional[Tuple[Dict[str, Any], HttpObservation, Optional[str]]]:
        marker_header = "X-Xasm-Trace-Control"
        obs = await self._request("TRACE", target + "/", extra_headers={marker_header: "present"})
        if obs.status is None or self._body_hash(obs.body) == negative_hash:
            return None
        lower_body = obs.body.lower()
        if marker_header.lower() not in lower_body:
            return None
        disclosed = sorted(name for name in TRUSTED_HEADER_NAMES if name + ":" in lower_body)
        if not disclosed:
            return None
        return ({
            "kind": "trusted_header_trace",
            "title": "TRACE Discloses a Trusted Internal Authorization Header",
            "severity": "medium",
            "marker": ",".join(disclosed),
            "description": "TRACE reflected a trusted authorization header added downstream.",
            "remediation": "Disable TRACE and never base authorization on spoofable forwarded headers.",
        }, obs, None)

    def _classify_verbose_error(
        self, baseline: HttpObservation, attack: HttpObservation,
    ) -> Optional[Dict[str, Any]]:
        if baseline.status is None or attack.status is None:
            return None
        lowered = attack.body.lower()
        has_stack = any(marker in lowered for marker in STACK_MARKERS)
        version = None
        for pattern in VERSION_PATTERNS:
            match = pattern.search(attack.body)
            if match:
                version = match.group(1)
                break
        baseline_has = any(marker in baseline.body.lower() for marker in STACK_MARKERS)
        if attack.status < 500 or baseline.status >= 500 or baseline_has or not (has_stack or version):
            return None
        marker = version or next(marker for marker in STACK_MARKERS if marker in lowered)
        return {
            "kind": "verbose_error",
            "title": "Verbose Application Error Discloses Internal Details",
            "severity": "low",
            "marker": marker,
            "description": "A type-mismatched observed parameter produced a differential verbose server error.",
            "remediation": "Return generic client errors and keep stack traces and framework details server-side.",
        }

    def _classify_debug(
        self, obs: HttpObservation, negative_hash: str,
    ) -> Optional[Dict[str, Any]]:
        if obs.status != 200 or not obs.body or self._body_hash(obs.body) == negative_hash:
            return None
        text = self._visible_text(obs.body)
        secret = SECRET_ASSIGNMENT_RE.search(text)
        if secret:
            raw = secret.group(2).rstrip(".,;)")
            if len(raw) >= 8 and raw.lower() not in {"changeme", "password", "example", "redacted"}:
                return {
                    "kind": secret.group(1).lower().replace("-", "_"),
                    "title": "Debug Endpoint Exposes a Sensitive Configuration Value",
                    "severity": "high",
                    "description": "A public diagnostic response exposes a credential-shaped configuration value.",
                    "remediation": "Remove debug endpoints from production and rotate the disclosed secret.",
                    "_rawValue": raw,
                }
        connection = CONNECTION_SECRET_RE.search(text)
        if connection:
            return {
                "kind": "connection_string",
                "title": "Debug Endpoint Exposes a Database Connection String",
                "severity": "high",
                "description": "A public diagnostic response exposes a credential-bearing connection string.",
                "remediation": "Remove debug endpoints and rotate all credentials in the disclosed connection string.",
                "_rawValue": connection.group(0),
            }
        if any(marker in text.lower() for marker in DEBUG_MARKERS):
            return {
                "kind": "debug_diagnostics",
                "title": "Public Debug or Diagnostic Endpoint",
                "severity": "medium",
                "marker": next(marker for marker in DEBUG_MARKERS if marker in text.lower()),
                "description": "A public endpoint exposes detailed runtime diagnostics.",
                "remediation": "Disable or strongly authenticate diagnostic endpoints in production.",
            }
        return None

    def _classify_directory_listing(
        self,
        obs: HttpObservation,
        target: str,
        negative_hash: str,
    ) -> Optional[Dict[str, Any]]:
        """Confirm a real same-origin autoindex and retain only bounded entry paths."""
        if (
            obs.status != 200
            or not self._is_html(obs)
            or self._body_hash(obs.body) == negative_hash
            or not AUTOINDEX_RE.search(obs.body)
        ):
            return None

        parser = _AutoindexEntryParser()
        try:
            parser.feed(obs.body)
        except Exception:
            return None

        listing_path = urlparse(obs.url).path or "/"
        entries: List[str] = []
        for raw in parser.urls:
            raw_value = str(raw or "").strip()
            if not raw_value or raw_value.startswith(("?", "#")) or raw_value in {".", "..", "./", "../"}:
                continue
            absolute = self._safe_same_origin_url(target, obs.url, raw_value)
            if not absolute:
                continue
            parsed = urlparse(absolute)
            if parsed.path == listing_path or parsed.path.rstrip("/") == listing_path.rstrip("/"):
                continue
            # Evidence is deliberately path-only. Autoindexes may expose signed
            # download URLs; persisting their query string would leak credentials.
            entry = parsed.path
            if entry not in entries:
                entries.append(entry[:512])
            if len(entries) >= 20:
                break

        # The heading alone can be application-authored text. At least one
        # concrete same-origin child makes the autoindex proof reproducible.
        if not entries:
            return None
        return {
            "kind": "directory_listing",
            "title": "Web Directory Listing Enabled",
            "severity": "low",
            "marker": f"Index of {listing_path}; entries={len(entries)}",
            "description": (
                "The web server exposes an automatically generated directory index with "
                "unauthenticated child paths."
            ),
            "remediation": (
                "Disable automatic directory indexing, add an explicit index document, and "
                "review the exposed paths for sensitive content."
            ),
            "evidence": {
                "listingPath": listing_path,
                "directoryEntries": entries,
                "directoryEntryCount": len(entries),
            },
        }

    def _classify_source(self, obs: HttpObservation) -> Optional[Dict[str, Any]]:
        lowered = obs.body.lower()
        if not any(marker.lower() in lowered for marker in SOURCE_MARKERS):
            return None
        secret = SECRET_ASSIGNMENT_RE.search(self._visible_text(obs.body))
        if secret:
            raw = secret.group(2).rstrip(".,;)")
            return {
                "kind": "backup_secret",
                "title": "Backup Source File Exposes a Sensitive Value",
                "severity": "high",
                "description": "A publicly served backup contains readable source and a credential-shaped value.",
                "remediation": "Remove backup files from the web root and rotate the exposed credential.",
                "_rawValue": raw,
            }
        return {
            "kind": "backup_source",
            "title": "Backup File Exposes Application Source Code",
            "severity": "medium",
            "marker": next(marker for marker in SOURCE_MARKERS if marker.lower() in lowered),
            "description": "A publicly served backup contains readable application source code.",
            "remediation": "Remove backup/editor files from the web root and deny backup suffixes.",
        }

    async def _maybe_finalize_lab(
        self,
        *,
        target: str,
        root_before: HttpObservation,
        raw_value: Optional[str],
        proof_level: str,
        engagement: str,
        approved: bool,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "solvedBefore": self._is_solved(root_before.body),
            "effectTriggered": False,
            "solvedAfter": self._is_solved(root_before.body),
            "transactions": [],
        }
        if (
            proof_level != LAB_PROOF
            or engagement not in {"lab", "ctf"}
            or not approved
            or not raw_value
            or result["solvedBefore"]
        ):
            return result
        submit = await self._request(
            "POST",
            target + "/submitSolution",
            data={"answer": raw_value},
            transcript_body="answer=[REDACTED:value-sha256=" + self._sha(raw_value) + "]",
        )
        correct = False
        try:
            payload = json.loads(submit.body)
            correct = payload.get("correct") is True
        except Exception:
            correct = '"correct":true' in submit.body.replace(" ", "").lower()
        after = await self._request("GET", target + "/")
        solved_after = self._is_solved(after.body)
        result.update({
            "effectTriggered": bool(correct),
            "solvedAfter": solved_after,
            "solutionAnswerSha256": self._sha(raw_value),
            "transactions": [
                self._transaction("lab-solution-submit", submit, raw_value),
                self._transaction("lab-solved-confirmation", after, raw_value),
            ],
        })
        return result

    def _finding(
        self,
        hit: Dict[str, Any],
        obs: HttpObservation,
        raw_value: Optional[str],
        transactions: List[Dict[str, str]],
        solution: Dict[str, Any],
    ) -> Dict[str, Any]:
        request = transactions[0]["request"]
        response = transactions[0]["response"]
        extracted = [f"kind:{hit['kind']}"]
        if raw_value:
            safe = self._safe_value(hit["kind"], raw_value)
            extracted.extend([
                f"value:{safe['masked']}",
                f"sha256:{safe['sha256']}",
                f"length:{safe['length']}",
            ])
        elif hit.get("marker"):
            extracted.append("marker:" + str(hit["marker"])[:200])
        if solution.get("solutionAnswerSha256"):
            extracted.append("solution-answer-sha256:" + solution["solutionAnswerSha256"])
        template_id = "xasm-information-disclosure-" + re.sub(r"[^a-z0-9]+", "-", hit["kind"].lower()).strip("-")
        return {
            "template-id": template_id,
            "templateID": template_id,
            "matched-at": obs.url,
            "matched": obs.url,
            "host": obs.url,
            "matcher-name": hit["kind"],
            "extracted-results": extracted,
            "request": request,
            "response": response,
            "observedTranscript": transactions,
            "evidence": {
                "request": request,
                "response": response,
                "httpTransactions": transactions,
                "fallback": False,
                "verified": True,
                "proofLevel": LAB_PROOF if solution.get("solutionAnswerSha256") else RUNTIME_PROOF,
                **(hit.get("evidence") if isinstance(hit.get("evidence"), dict) else {}),
            },
            "info": {
                "name": hit["title"],
                "severity": hit["severity"],
                "description": hit["description"],
                "remediation": hit["remediation"],
                "classification": {"cwe-id": ["CWE-200"]},
            },
        }

    async def _cached_get(self, url: str) -> HttpObservation:
        if url in self._observations:
            return self._observations[url]
        return await self._request("GET", url)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        data: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        transcript_body: Optional[str] = None,
    ) -> HttpObservation:
        method = method.upper()
        request_headers = dict(self._session.headers)
        if extra_headers:
            request_headers.update(extra_headers)
        if self._requests >= self._budget:
            return HttpObservation(method, url, None, request_headers, {}, "")
        self._requests += 1
        try:
            async with self._session.request(
                method,
                url,
                data=data,
                headers=extra_headers,
                allow_redirects=False,
            ) as response:
                # StreamReader.read(n) may return the first available chunk
                # instead of waiting for EOF. Accumulate bounded chunks so
                # evidence near the end of gzip/chunked diagnostic pages is
                # still inspected without permitting an unbounded response.
                chunks: List[bytes] = []
                remaining = self._max_bytes + 1
                while remaining > 0:
                    chunk = await response.content.read(min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)[: self._max_bytes]
                self._bytes += len(raw)
                body = raw.decode(response.charset or "utf-8", "replace")
                obs = HttpObservation(
                    method=method,
                    url=str(response.url),
                    status=response.status,
                    request_headers=request_headers,
                    response_headers={str(k): str(v) for k, v in response.headers.items()},
                    body=body,
                )
                if transcript_body is not None:
                    setattr(obs, "_transcript_body", transcript_body)
                if method == "GET":
                    self._observations[url] = obs
                return obs
        except Exception:
            return HttpObservation(method, url, None, request_headers, {}, "")

    def _transaction(
        self, label: str, obs: HttpObservation, raw_value: Optional[str],
    ) -> Dict[str, str]:
        return {
            "label": label,
            "request": self._request_transcript(obs, raw_value),
            "response": self._response_transcript(obs, raw_value),
        }

    def _request_transcript(
        self, obs: HttpObservation, raw_value: Optional[str],
    ) -> str:
        parsed = urlparse(obs.url)
        safe_pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if re.search(r"(?i)(?:secret|passw|token|key|auth|session|csrf|xsrf)", key):
                safe_pairs.append((key, "[REDACTED]"))
            else:
                safe_pairs.append((key, value))
        target = urlunparse(
            ("", "", parsed.path or "/", "", urlencode(safe_pairs, doseq=True), ""),
        )
        lines = [f"{obs.method} {target} HTTP/1.1", f"Host: {parsed.netloc}"]
        for key, value in obs.request_headers.items():
            if key.lower() in {"host", "content-length"}:
                continue
            safe = "[REDACTED]" if SENSITIVE_HEADER_RE.match(key) else self._sanitize_text(value, raw_value)
            lines.append(f"{key}: {safe}")
        transcript_body = getattr(obs, "_transcript_body", None)
        if transcript_body:
            lines.extend(["Content-Type: application/x-www-form-urlencoded", "", transcript_body])
        return "\r\n".join(lines) + "\r\n\r\n"

    def _response_transcript(self, obs: HttpObservation, raw_value: Optional[str]) -> str:
        lines = [f"HTTP/1.1 {obs.status if obs.status is not None else 'N/A'}"]
        for key, value in obs.response_headers.items():
            safe = "[REDACTED]" if SENSITIVE_HEADER_RE.match(key) else self._sanitize_text(value, raw_value)
            lines.append(f"{key}: {safe}")
        body_source = obs.body
        if raw_value and len(body_source) > 12000:
            marker_index = body_source.find(raw_value)
            if marker_index >= 0:
                start = max(0, marker_index - 4000)
                end = min(len(body_source), marker_index + len(raw_value) + 4000)
                body_source = "[... earlier response bytes omitted ...]\n" + body_source[start:end]
        body = self._sanitize_body(body_source, raw_value)
        if body:
            lines.extend(["", body[:12000]])
        return "\r\n".join(lines)

    def _sanitize_body(self, body: str, raw_value: Optional[str]) -> str:
        safe = self._sanitize_text(str(body or ""), raw_value)
        safe = SENSITIVE_QUERY_VALUE_RE.sub(r"\1[REDACTED]", safe)
        replacements: List[Tuple[str, str]] = []
        visible = self._visible_text(safe)
        for match in SECRET_ASSIGNMENT_RE.finditer(visible):
            value = match.group(2).rstrip(".,;)")
            if value:
                replacements.append((value, "[REDACTED:secret-sha256=" + self._sha(value) + "]"))
        for match in CONNECTION_SECRET_RE.finditer(safe):
            replacements.append((match.group(0), "[REDACTED:connection-string-sha256=" + self._sha(match.group(0)) + "]"))
        # Diagnostic pages such as phpinfo can echo server-created cookies that
        # were never present in the workflow's injected auth context. Discover
        # those incidental values in both ordinary cookie pairs and rendered
        # PHP-variable tables, then replace every occurrence before Job.output
        # or finding evidence can be persisted.
        for pattern in (COOKIE_PAIR_RE, COOKIE_TABLE_VALUE_RE):
            for match in pattern.finditer(visible):
                value = match.group(1).rstrip(".,;)")
                if value:
                    replacements.append(
                        (value, "[REDACTED:session-sha256=" + self._sha(value) + "]"),
                    )
        if PRIVATE_KEY_RE.search(safe):
            safe = re.sub(
                r"(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?"
                r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
                "[REDACTED:private-key]",
                safe,
            )
        for value, replacement in replacements:
            safe = safe.replace(value, replacement)
        return safe

    def _sanitize_text(self, value: str, raw_value: Optional[str]) -> str:
        safe = str(value or "")
        replacements = list(self._private_values)
        if raw_value:
            replacements.append(raw_value)
        for secret_value in sorted(set(replacements), key=len, reverse=True):
            if secret_value:
                safe = safe.replace(
                    secret_value,
                    "[REDACTED:value-sha256=" + self._sha(secret_value) + "]",
                )
        return safe

    def _safe_value(self, kind: str, value: str) -> Dict[str, Any]:
        return {
            "type": kind,
            "masked": self._mask(value),
            "sha256": self._sha(value),
            "length": len(value),
        }

    def _safe_same_origin_url(
        self, target: str, base: str, raw: str,
    ) -> Optional[str]:
        raw = str(raw or "").strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        absolute = urljoin(base, raw)
        parsed = urlparse(absolute)
        root = urlparse(target)
        if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != root.netloc.lower():
            return None
        if self._skip_navigation(parsed.path):
            return None
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))

    def _robots_paths(self, body: str, target: str) -> List[str]:
        out: List[str] = []
        for value in re.findall(r"(?im)^\s*(?:disallow|allow):\s*([^#\s]+)", body):
            if "*" in value or "$" in value:
                continue
            candidate = self._safe_same_origin_url(target, target + "/robots.txt", value)
            if candidate:
                out.append(candidate)
        return self._dedupe(out)[:12]

    def _is_html(self, obs: HttpObservation) -> bool:
        content_type = next(
            (v for k, v in obs.response_headers.items() if k.lower() == "content-type"), ""
        ).lower()
        return "html" in content_type or bool(HTML_RE.search(obs.body[:2048]))

    def _visible_text(self, body: str) -> str:
        return re.sub(r"\s+", " ", html.unescape(re.sub(r"(?s)<[^>]+>", " ", body or ""))).strip()

    def _is_solved(self, body: str) -> bool:
        lowered = (body or "").lower()
        return "is-solved" in lowered and "is-notsolved" not in lowered

    def _origin(self, raw: Any) -> Optional[str]:
        value = str(raw or "").strip()
        if not value:
            return None
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    def _skip_navigation(self, path: str) -> bool:
        return bool(UNSAFE_PATH_RE.search(path or ""))

    def _static_extension(self, path: str) -> bool:
        return bool(re.search(r"\.(?:css|jpe?g|gif|png|svg|ico|woff2?|pdf|zip|gz|mp[34])$", path, re.I))

    def _body_hash(self, body: str) -> str:
        normalized = re.sub(r"\s+", " ", str(body or "")).strip()
        return hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()

    def _sha(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()

    def _mask(self, value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        shown = min(len(value), 12)
        return value[:2] + "*" * (shown - 4) + value[-2:] + f" (len={len(value)})"

    def _bounded_int(self, value: Any, default: int, low: int, high: int) -> int:
        try:
            return max(low, min(int(value), high))
        except (TypeError, ValueError):
            return default

    def _dedupe(self, values: Iterable[str]) -> List[str]:
        seen: set[str] = set()
        out: List[str] = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                out.append(value)
        return out

    def _without_none(self, value: Dict[str, Any]) -> Dict[str, Any]:
        return {key: item for key, item in value.items() if item is not None}

    def _error(self, message: str, target: Optional[str] = None) -> Dict[str, Any]:
        return {
            "success": False,
            "tool": self.name,
            "target": target,
            "verified": False,
            "fallback": False,
            "error": message,
            "findings": [],
        }


def get_tool() -> WebInformationDisclosureProbeTool:
    return WebInformationDisclosureProbeTool()
