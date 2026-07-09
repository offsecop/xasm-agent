"""
cloud:app_settings_secret_scan — cloud-storage credentials disclosed in AUTHENTICATED
application settings pages, plus an anonymous S3/MinIO bucket-listing probe.

Scope is deliberately the part nothing else on the platform does. The generic secret
SIGNAL is already owned elsewhere, so this tool is their COMPLEMENT, never a duplicate:
  • `lfi:file_exposure_probe` (#318) owns secrets reached by `../` traversal of a
    download/file parameter (.env / SSH keys / config files) — this tool NEVER does a
    naive root `GET /.env` and NEVER path-traverses.
  • `git:source_disclosure_scanner` (#324) owns secrets mined from an exposed `.git`
    history — this tool NEVER touches `.git`.
  • `origami:client_secret_scan` owns secrets in PUBLIC client-side JS/HTML.
This tool's unique surface is the secret rendered inside an AUTHENTICATED settings/admin
PAGE (an S3/MinIO endpoint + access key + secret in the app's own "Filesystem Settings"
UI), plus the genuinely-new active step: probing the discovered object-storage endpoint
for an anonymous/public bucket listing. Source TTP: HTB Facts #3 (corpus
research/htb-writeups/easy/Facts.md) — Camaleon CMS leaks MinIO creds in Settings →
Filesystem Settings, unlocking `aws --endpoint-url http://facts.htb:9000 s3 ls`.

Findings mirror the Nuclei envelope so the backend reuses `processNucleiOutput`
(ingestion signature `CLOUD_CREDENTIAL_EXPOSURE`). Pairs with `cloud:aws_enum` (#334,
post-credential enumeration) under the same signature family but distinct template-ids.
All recovered secrets are reported REDACTED (label + masked preview + sha256), never raw.
"""

import asyncio
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp

from plugin_interface import ToolPlugin


# Authenticated settings/admin PAGES likely to render storage config. These are app
# routes (UI), not on-disk config files — fetching `.env`/appsettings.json at the web
# root is #318's surface and is intentionally excluded here.
DEFAULT_SETTINGS_PATHS = [
    "/admin/settings",
    "/admin/settings/filesystem",
    "/admin/settings/storage",
    "/admin/config",
    "/admin/configuration",
    "/admin/system",
    "/admin/storage",
    "/admin",
    "/settings",
    "/settings/storage",
    "/dashboard/settings",
    "/manage/settings",
    "/account/settings",
]

HTML_MARKERS = ("<!doctype html", "<html", "<head", "<body")
LOGIN_MARKERS = ("user[password]", 'type="password"', "/admin/login", "sign in", "login")

# Self-identifying AWS/compatible access-key id. Low-FP: the shape is unambiguous.
AWS_KEYID_RE = re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16})\b")

# Cloud-storage credential key-names. group(1)=keyname. Used in two extraction modes
# (KEY=VALUE config/JSON, and HTML <input name=...> value=...).
CLOUD_KEYNAME_RE = re.compile(
    r"""(?ix)\b(
        s3[_\- ]?(?:endpoint|secret(?:[_\- ]?key)?|access[_\- ]?key|key|bucket|region|host)
      | minio[_\- ]?(?:endpoint|root[_\- ]?user|root[_\- ]?password|access[_\- ]?key|secret[_\- ]?key|host)
      | aws[_\- ]?(?:access[_\- ]?key[_\- ]?id | secret[_\- ]?access[_\- ]?key)
      | (?:spaces|storage|bucket)[_\- ]?(?:access[_\- ]?key|secret(?:[_\- ]?key)?|endpoint)
    )\b""",
)

# KEY (=|:) VALUE for config/env/JSON-rendered settings.
CLOUD_KV_RE = re.compile(
    r"""(?ix)
    \b(
        s3[_\- ]?(?:endpoint|secret(?:[_\- ]?key)?|access[_\- ]?key|key|bucket|region|host)
      | minio[_\- ]?(?:endpoint|root[_\- ]?user|root[_\- ]?password|access[_\- ]?key|secret[_\- ]?key|host)
      | aws[_\- ]?(?:access[_\- ]?key[_\- ]?id | secret[_\- ]?access[_\- ]?key)
      | (?:spaces|storage)[_\- ]?(?:access[_\- ]?key|secret(?:[_\- ]?key)?|endpoint)
    )\b
    \s*['"]?\s*[:=]\s*['"]?
    ([^\s'"<>&;]{4,256})
    """,
)

INPUT_TAG_RE = re.compile(r"<(?:input|textarea)\b[^>]*>", re.IGNORECASE)
ATTR_RE = re.compile(r'([a-zA-Z][\w:-]*)\s*=\s*"([^"]*)"')

# S3/MinIO endpoint URL or host:port shape (used to seed the bucket probe).
ENDPOINT_RE = re.compile(
    r"""(?ix)\b(
        https?://[a-z0-9.\-_]+(?::\d{2,5})?
      | [a-z0-9.\-_]+:(?:9000|9001|443)
    )\b""",
)

# S3 ListBuckets / ListObjects XML — the anonymous-listing oracle.
S3_XML_MARKERS = (
    "<listallmybucketsresult",
    "<listbucketresult",
    "<buckets>",
    "<bucket>",
)

# Only these classifications are reported as a credential disclosure. An endpoint /
# bucket / region is a descriptor used to SEED the bucket probe, never itself a "secret".
CREDENTIAL_TYPES = {"aws_access_key_id", "s3_access_key", "s3_secret_key", "cloud_storage_secret"}

# Obvious non-secret placeholders / vendor doc examples — never reported.
PLACEHOLDERS = {
    "", "null", "none", "true", "false", "changeme", "example", "test", "secret",
    "your_key", "your_secret", "your-access-key", "access_key", "secret_key",
    "akiaiosfodnn7example", "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
    "minioadmin", "xxxxxxxx", "redacted", "...", "********", "<key>", "<secret>",
}


class CloudAppSettingsSecretScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "cloud:app_settings_secret_scan"

    @property
    def description(self) -> str:
        return (
            "Crawls AUTHENTICATED settings/admin pages for cloud-storage credential shapes "
            "(AWS AKIA keys, S3/MinIO endpoint+access-key+secret) and probes the discovered "
            "object-storage endpoint for an anonymous/public bucket listing. The complement "
            "to lfi:file_exposure_probe (.env via traversal), git:source_disclosure_scanner "
            "(.git history) and origami:client_secret_scan (public JS) — it owns the secret "
            "rendered inside the app's own authenticated settings UI. Secrets reported redacted."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Base URL of the application"},
                "url": {"type": "string", "description": "Alias for target"},
                "enabled": {"type": "boolean", "default": True},
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Authenticated page URLs to scan (e.g. from a crawl step)",
                },
                "settingsPaths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Settings/admin UI paths to probe (relative to target)",
                },
                "cookie": {"type": "string", "description": "Authenticated session cookie header value"},
                "authCookies": {"type": "string", "description": "Alias for cookie"},
                "headers": {"type": "object", "description": "Extra HTTP headers"},
                "probeBuckets": {
                    "type": "boolean",
                    "default": True,
                    "description": "Probe discovered S3/MinIO endpoints for anonymous bucket listing",
                },
                "maxRequests": {"type": "integer", "default": 120},
                "timeoutSeconds": {"type": "integer", "default": 15},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "vuln-scan",
            "phase": 4,
            "domain": ["web", "cloud"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["authentication:", "katana:", "httpx:", "api:"],
            "chainable_before": ["cloud:", "decision:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        if parameters.get("enabled") is False:
            return {"success": True, "skipped": True, "tool": self.name, "findings": []}

        raw_target = parameters.get("target") or parameters.get("url") or ""
        origin = self._origin(raw_target)
        if not origin:
            return {"success": False, "error": f"target must be an http(s) URL: {raw_target!r}"}

        timeout_s = max(3, min(int(parameters.get("timeoutSeconds") or 15), 120))
        self._max_requests = max(3, min(int(parameters.get("maxRequests") or 120), 2000))
        self._reqs = 0
        probe_buckets = bool(parameters.get("probeBuckets", True))
        agent = parameters.get("_agent")

        headers = {"User-Agent": "xASM-cloud-app-settings-secret-scan/1.0", "Accept": "*/*"}
        extra = parameters.get("headers")
        if isinstance(extra, dict):
            headers.update({str(k): str(v) for k, v in extra.items()})
        cookie = parameters.get("cookie") or parameters.get("authCookies")
        if cookie:
            headers["Cookie"] = str(cookie)

        # Build the page work-list: explicit urls + settings paths under the origin.
        pages: List[str] = []
        seen_pages = set()
        for u in (parameters.get("urls") or []):
            cu = self._coerce_url(u, origin)
            if cu and cu not in seen_pages:
                seen_pages.add(cu)
                pages.append(cu)
        settings_paths = parameters.get("settingsPaths") or DEFAULT_SETTINGS_PATHS
        for p in settings_paths:
            cu = urljoin(origin + "/", str(p).lstrip("/"))
            if cu not in seen_pages:
                seen_pages.add(cu)
                pages.append(cu)

        findings: List[Dict[str, Any]] = []
        creds: Dict[str, Dict[str, Any]] = {}   # value -> cred record (global dedup)
        endpoints: Dict[str, str] = {}          # normalized endpoint -> source page
        buckets: set = set()                    # discovered bucket names (probe targets)
        pages_with_creds = 0

        connector = aiohttp.TCPConnector(ssl=False, limit=8)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout_s),
            headers=headers,
        ) as session:
            self._session = session

            # Stage 1 — crawl authenticated settings pages for cloud-cred shapes.
            for idx, page in enumerate(pages):
                status, body = await self._get(page)
                if agent:
                    agent.report_progress("Scanning settings page", page, idx + 1, len(pages))
                text = self._validated_text(status, body)
                if text is None:
                    continue
                hits = self._scan_page(text)
                if not hits:
                    continue
                page_had_cred = False
                for ctype, value, endpoint in hits:
                    if endpoint:
                        norm = self._normalize_endpoint(endpoint)
                        if norm and norm not in endpoints:
                            endpoints[norm] = page
                    if ctype == "s3_bucket":
                        buckets.add(value)
                    # Endpoint / bucket / region are probe-seeds, never a credential finding.
                    if ctype not in CREDENTIAL_TYPES:
                        continue
                    # Dedup by secret VALUE (global across pages). _scan_page yields the
                    # self-identifying AWS-key classification first, so a value that is both
                    # an AKIA key and sits in an "s3_access_key" field is reported once, under
                    # the most-specific type — never double-counted.
                    if value in creds:
                        continue
                    rec = {
                        "type": ctype,
                        "masked": self._mask(value),
                        "sha256": hashlib.sha256(value.encode("utf-8", "replace")).hexdigest(),
                        "page": page,
                    }
                    creds[value] = rec
                    page_had_cred = True
                    findings.append(self._cred_finding(page, rec))
                if page_had_cred:
                    pages_with_creds += 1

            # Stage 2 — probe each discovered endpoint for an anonymous public listing.
            probed = 0
            public_buckets = 0
            if probe_buckets and endpoints:
                for endpoint, src in endpoints.items():
                    if self._is_unreachable_host(endpoint):
                        continue  # loopback / link-local: meaningless from the scanner vantage
                    probed += 1
                    listing = await self._probe_bucket(endpoint, buckets)
                    if agent:
                        agent.report_progress("Probing object-storage endpoint", endpoint, probed, len(endpoints))
                    if listing:
                        public_buckets += 1
                        findings.append(self._bucket_finding(endpoint, src, listing))

        raw_lines = [f"[{f['info']['severity'].upper()}] {f['info']['name']} - {f['matched-at']}" for f in findings]
        return {
            "success": True,
            "tool": self.name,
            "target": origin,
            "findings": findings,
            "total_findings": len(findings),
            "rawOutput": "\n".join(raw_lines),
            "summary": {
                "pagesScanned": len(pages),
                "pagesWithCreds": pages_with_creds,
                "credentialsDisclosed": len(creds),
                "endpointsDiscovered": len(endpoints),
                "endpointsProbed": probed if probe_buckets else 0,
                "publicBuckets": public_buckets if probe_buckets else 0,
                "requests": self._reqs,
            },
        }

    # ----- HTTP -----
    async def _get(self, url: str) -> Tuple[Optional[int], bytes]:
        if self._reqs >= self._max_requests:
            return None, b""
        self._reqs += 1
        try:
            async with self._session.get(url, allow_redirects=False) as resp:
                body = await resp.content.read(1_000_000)
                return resp.status, body
        except Exception:
            return None, b""

    def _validated_text(self, status: Optional[int], body: bytes) -> Optional[str]:
        """Only an authenticated 200 settings page is worth scanning. A 3xx means the
        session is not authenticated (redirect to login); a pure login page has no
        cred shapes and is filtered by extraction. Reject empty bodies."""
        if status != 200 or not body:
            return None
        text = body.decode("utf-8", "replace")
        head = text[:2048].lower()
        # A login/redirect shell with NO cloud-key name present is never a settings leak.
        if any(m in head for m in LOGIN_MARKERS) and not CLOUD_KEYNAME_RE.search(text):
            return None
        return text

    # ----- extraction -----
    def _scan_page(self, text: str) -> List[Tuple[str, str, Optional[str]]]:
        """Return [(cred_type, value, endpoint_or_None)]."""
        hits: List[Tuple[str, str, Optional[str]]] = []

        # 1. Self-identifying AWS/compatible access-key ids.
        for m in AWS_KEYID_RE.finditer(text):
            val = m.group(1)
            if self._plausible(val, "aws_access_key_id"):
                hits.append(("aws_access_key_id", val, None))

        # 2. KEY=VALUE / KEY: VALUE config/JSON rendering.
        for m in CLOUD_KV_RE.finditer(text):
            keyname, value = m.group(1), m.group(2).strip().strip("'\"")
            ctype = self._classify(keyname)
            if self._plausible(value, ctype):
                hits.append((ctype, value, value if ctype.endswith("endpoint") else self._endpoint_in(value)))

        # 3. HTML form inputs whose name/id matches a cloud key-name → its value attr.
        for tag in INPUT_TAG_RE.finditer(text):
            attrs = dict(ATTR_RE.findall(tag.group(0)))
            nm = f"{attrs.get('name','')} {attrs.get('id','')}".lower()
            val = (attrs.get("value") or "").strip()
            if not val or not CLOUD_KEYNAME_RE.search(nm):
                continue
            ctype = self._classify(nm)
            if self._plausible(val, ctype):
                hits.append((ctype, val, val if ctype.endswith("endpoint") else self._endpoint_in(val)))

        return hits

    def _classify(self, keyname: str) -> str:
        k = keyname.lower()
        if "endpoint" in k or "host" in k:
            return "s3_endpoint"
        if "secret" in k or "root_password" in k or "rootpassword" in k:
            return "s3_secret_key"
        if "access" in k or "root_user" in k or "rootuser" in k or k.endswith("key"):
            return "s3_access_key"
        if "bucket" in k:
            return "s3_bucket"
        if "region" in k:
            return "s3_region"
        return "cloud_storage_secret"

    def _plausible(self, value: str, ctype: str) -> bool:
        v = (value or "").strip()
        if not v or v.lower() in PLACEHOLDERS:
            return False
        # Endpoints/buckets/regions are descriptors, not secrets — looser length gate.
        if ctype in ("s3_endpoint", "s3_bucket", "s3_region"):
            return 3 <= len(v) <= 256 and not v.startswith("<")
        if ctype == "aws_access_key_id":
            return bool(re.fullmatch(r"(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}", v))
        # Secret material: require some length + not a bare word/placeholder.
        if len(v) < 6 or len(v) > 256:
            return False
        if v.lower() in PLACEHOLDERS or v.isalpha() and len(v) < 10:
            return False
        return True

    def _endpoint_in(self, value: str) -> Optional[str]:
        m = ENDPOINT_RE.search(value or "")
        return m.group(1) if m else None

    # ----- endpoint / bucket probe -----
    def _normalize_endpoint(self, ep: str) -> Optional[str]:
        ep = (ep or "").strip().strip("'\"")
        if not ep:
            return None
        if "://" not in ep:
            ep = "http://" + ep
        p = urlparse(ep)
        if p.scheme not in {"http", "https"} or not p.netloc:
            return None
        # Preserve any base path (drop query/fragment + trailing slash). A real S3/MinIO
        # endpoint carries no path so this is a no-op there; a path-prefixed endpoint is
        # probed at that prefix. The probe appends "/", "/?list-type=2", "/probe/".
        path = p.path.rstrip("/")
        return urlunparse((p.scheme, p.netloc, path, "", "", ""))

    def _is_unreachable_host(self, endpoint: str) -> bool:
        host = urlparse(endpoint).hostname or ""
        h = host.lower()
        return (
            h in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
            or h.startswith("127.")
            or h.startswith("169.254.")
        )

    async def _probe_bucket(self, endpoint: str, buckets: Optional[set] = None) -> Optional[str]:
        """GET the endpoint root (ListBuckets) + each discovered bucket (ListObjects); return
        an evidence snippet iff a response is genuine S3 XML (anonymous public listing)."""
        candidates = [endpoint + "/", endpoint + "/?list-type=2"]
        for b in sorted(buckets or [])[:5]:
            bp = b.strip().strip("/")
            if bp:
                candidates.append(f"{endpoint}/{bp}/")
                candidates.append(f"{endpoint}/{bp}/?list-type=2")
        for url in candidates:
            status, body = await self._get(url)
            if status != 200 or not body:
                continue
            head = body[:4096].decode("utf-8", "replace")
            low = head.lower()
            if any(m in low for m in HTML_MARKERS):
                continue  # an HTML page is not an S3 XML listing
            if any(m in low for m in S3_XML_MARKERS):
                return head[:600]
        return None

    # ----- findings (Nuclei-shaped) -----
    def _cred_finding(self, page: str, rec: Dict[str, Any]) -> Dict[str, Any]:
        ctype = rec["type"]
        return self._finding(
            template_id=f"xasm-cloud-cred-{ctype.replace('_','-')}",
            name="Cloud Storage Credential Disclosed in Application Settings",
            severity="high",
            matched_at=page,
            description=(
                f"A cloud object-storage credential ({ctype}) is rendered in an authenticated "
                f"application settings page ({page}). Anyone who reaches this settings UI — or "
                "escalates to it via a separate access-control flaw — recovers working storage "
                "credentials. (The secret is reported redacted; raw value never stored.)"
            ),
            remediation=(
                "Never render storage secrets in the settings UI; store them server-side "
                "(secret manager / env), show only a masked indicator, and rotate any exposed key."
            ),
            matcher_name=f"cloud-cred:{ctype}",
            extracted=[
                f"type:{ctype}",
                f"value:{rec['masked']}",
                f"sha256:{rec['sha256']}",
                f"source-page:{page}",
            ],
        )

    def _bucket_finding(self, endpoint: str, source_page: str, evidence: str) -> Dict[str, Any]:
        sample = re.sub(r"\s+", " ", evidence).strip()[:300]
        return self._finding(
            template_id="xasm-cloud-bucket-public",
            name="Anonymous/Public S3/MinIO Bucket Listing",
            severity="critical",
            matched_at=endpoint,
            description=(
                f"The object-storage endpoint {endpoint} (discovered from credentials leaked in "
                f"{source_page}) returns an S3 ListBuckets/ListObjects response to an "
                "unauthenticated request — its contents are anonymously enumerable."
            ),
            remediation=(
                "Disable anonymous access on the bucket/endpoint, require signed requests, and "
                "audit the objects that were publicly listable."
            ),
            matcher_name="cloud-bucket:public-listing",
            extracted=[f"endpoint:{endpoint}", f"source-page:{source_page}", f"listing:{sample}"],
        )

    def _finding(self, *, template_id, name, severity, matched_at, description, remediation, matcher_name, extracted) -> Dict[str, Any]:
        return {
            "template-id": template_id,
            "templateID": template_id,
            "matched-at": matched_at,
            "matched": matched_at,
            "host": matched_at,
            "matcher-name": matcher_name,
            "extracted-results": [e for e in extracted if e],
            "info": {"name": name, "severity": severity, "description": description, "remediation": remediation},
        }

    # ----- helpers -----
    def _mask(self, value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}{'*' * (min(len(value), 12) - 4)}{value[-2:]} (len={len(value)})"

    def _coerce_url(self, u: str, origin: str) -> Optional[str]:
        u = str(u or "").strip()
        if not u:
            return None
        if u.startswith(("http://", "https://")):
            return u
        return urljoin(origin + "/", u.lstrip("/"))

    def _origin(self, raw: str) -> Optional[str]:
        raw = str(raw or "").strip()
        if not raw:
            return None
        if "://" not in raw:
            raw = "http://" + raw
        p = urlparse(raw)
        if p.scheme not in {"http", "https"} or not p.netloc:
            return None
        return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def get_tool():
    return CloudAppSettingsSecretScanTool()
