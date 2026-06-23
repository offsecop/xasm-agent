"""
Brand Discover Entities Tool (T5.4) — scrape-only VIP + social-handle
discovery.

Crawls a brand's public-facing surface (the homepage, common
about/team paths, press release indexes) and extracts:

  * VIPs (executives / leadership) — name + title + source URL
  * Social handles per supported platform (twitter/x, instagram,
    tiktok, linkedin, facebook, youtube)

OUTPUT SCHEMA (consumed by backend ingestion T5.5):

    {
      "vips":    [{ "name": str, "title": str|None,
                    "source_url": str, "confidence": float (0..1) }],
      "handles": [{ "platform": str, "handle": str,
                    "source_url": str, "confidence": float (0..1) }]
    }

DRP vendor scope (per the 2026-05-15 decision, see
docs/adrs/social-handles-storage.md and the §3.3 migration plan
note) — this tool MUST NOT call HIKER_API, SCRAPECREATORS, or
twitterapi.io. Wave 4B adds those wrappers separately as their own
tools so per-tenant `ProviderQuotaService.checkout()` can govern
spend. Until that lands, restrict to public scrape sources.

Implementation notes
--------------------
- Uses `requests` (already in agent/requirements.txt) and stdlib
  HTML parsing. We deliberately avoid httpx + beautifulsoup4 here
  to avoid a Dockerfile rebuild dependency; the regex + html.parser
  approach is sufficient for og:* meta + href= scraping.
- No Playwright launch — the existing brand_discover_vips tool does
  that, which is heavy. This is meant to be a cheap auto-dispatch
  on monitor create (T5.6).
- Common-handle "guesses" (e.g. `@brandname` on each platform) are
  flagged with low confidence (0.35) so the analyst confirm/reject
  flow surfaces them but doesn't auto-confirm.
"""

from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

from plugin_interface import ToolPlugin


# ──────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 10  # seconds per HTTP fetch
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36 ASMBrandDiscovery/1.0"
)

# Pages we'll fetch in addition to the homepage. Common paths used by
# corporate sites — most return 404 and are skipped silently.
DISCOVERY_PATHS = [
    "/",
    "/about",
    "/about-us",
    "/team",
    "/leadership",
    "/our-team",
    "/people",
    "/management",
    "/press",
    "/newsroom",
    "/news",
]

# Per-platform host patterns. The first entry wins for canonicalization.
SOCIAL_HOSTS: Dict[str, Tuple[str, ...]] = {
    "TWITTER_X": ("twitter.com", "x.com"),
    "INSTAGRAM": ("instagram.com",),
    "TIKTOK": ("tiktok.com",),
    "LINKEDIN": ("linkedin.com",),
    "FACEBOOK": ("facebook.com", "fb.com"),
    "YOUTUBE": ("youtube.com", "youtu.be"),
}

# URL patterns that look like handles per platform. Each regex captures
# the handle in group 1.
SOCIAL_HANDLE_PATTERNS: Dict[str, re.Pattern] = {
    "TWITTER_X": re.compile(
        r"^/(?:#!/)?([A-Za-z0-9_]{1,15})/?$"
    ),
    "INSTAGRAM": re.compile(
        r"^/([A-Za-z0-9._]{1,30})/?$"
    ),
    "TIKTOK": re.compile(
        r"^/@([A-Za-z0-9._]{1,24})/?$"
    ),
    "LINKEDIN": re.compile(
        r"^/(?:company|in|school)/([A-Za-z0-9._\-]{1,60})/?$"
    ),
    "FACEBOOK": re.compile(
        r"^/([A-Za-z0-9._\-]{1,50})/?$"
    ),
    "YOUTUBE": re.compile(
        r"^/(?:c|channel|user|@)([A-Za-z0-9._\-]{1,30})/?$"
    ),
}

# Paths on social hosts that are NOT user handles. Filtering them keeps
# us from proposing things like @about or @intent as Twitter handles.
SOCIAL_PATH_DENYLIST = {
    "share", "intent", "search", "explore", "hashtag", "i", "home",
    "login", "signup", "about", "tos", "privacy", "help", "developers",
    "settings", "messages", "notifications", "embed", "watch",
    "results", "feed", "pricing", "products", "company", "careers",
}

# Title keywords that mark a person as senior leadership. Used to keep
# only VIPs and drop arbitrary "About the author" name-droppings.
SENIORITY_TITLE_KEYWORDS = [
    "ceo", "cto", "cfo", "coo", "cio", "ciso", "cmo", "cro", "cpo",
    "chief", "president", "vp", "vice president", "founder",
    "co-founder", "director", "head of", "managing director",
    "general counsel", "general manager",
]


# ──────────────────────────────────────────────────────────────────
# Lightweight HTML scraper
# ──────────────────────────────────────────────────────────────────

class _DiscoveryParser(HTMLParser):
    """Single-pass HTML parser that collects:
        - og:* + twitter:* meta tag contents (dict)
        - all <a href=...> targets (list)
        - text-near-link spans for "Name — Title" extraction.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: Dict[str, str] = {}
        self.links: List[str] = []
        # (tag, text) chunks; we only keep heading / strong / p text
        # since that's where VIP names usually appear.
        self._text_buf: List[str] = []
        self._in_text_tag = False
        self.text_chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_d = {k: (v or "") for k, v in attrs}
        if tag == "meta":
            key = (attrs_d.get("property") or attrs_d.get("name") or "").lower()
            content = attrs_d.get("content") or ""
            if key and content:
                self.meta[key] = content
        elif tag == "a":
            href = attrs_d.get("href")
            if href:
                self.links.append(href)
        if tag in {"h1", "h2", "h3", "h4", "h5", "strong", "p"}:
            self._in_text_tag = True
            self._text_buf = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"h1", "h2", "h3", "h4", "h5", "strong", "p"} and self._in_text_tag:
            chunk = " ".join(self._text_buf).strip()
            if chunk:
                self.text_chunks.append(chunk)
            self._in_text_tag = False
            self._text_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_text_tag:
            d = data.strip()
            if d:
                self._text_buf.append(d)


# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────

def _fetch(url: str) -> Optional[str]:
    """Single GET. Returns None on any failure (network, non-2xx,
    non-HTML content-type, size cap exceeded)."""
    try:
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html"},
            allow_redirects=True,
        )
    except Exception:
        return None
    if r.status_code != 200:
        return None
    ctype = r.headers.get("content-type", "").lower()
    if "html" not in ctype and "xml" not in ctype:
        return None
    # 1 MiB cap — corporate homepages can be heavy but we don't need the
    # whole bundle; the og:* + visible text + nav links are in the head
    # + first few KB.
    if len(r.content) > 1_000_000:
        return r.content[:1_000_000].decode("utf-8", errors="replace")
    return r.text


def _normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    d = d.replace("https://", "").replace("http://", "").rstrip("/")
    return d


def _build_base_url(domain: str, website_url: Optional[str]) -> str:
    """Prefer the explicit websiteUrl when present; otherwise https://<domain>."""
    if website_url:
        wu = website_url.strip()
        if wu.startswith("http://") or wu.startswith("https://"):
            return wu.rstrip("/")
    return f"https://{_normalize_domain(domain)}"


def _classify_social_link(href: str) -> Optional[Tuple[str, str]]:
    """Map an href to (platform, handle) if it matches a known social host.
    Returns None for non-matches, denylisted paths, or unparseable handles.
    """
    try:
        p = urlparse(href)
    except Exception:
        return None
    host = (p.netloc or "").lower().lstrip("www.")
    if not host:
        return None
    # Find the platform whose hosts include this one.
    platform: Optional[str] = None
    for plat, hosts in SOCIAL_HOSTS.items():
        if any(host == h or host.endswith("." + h) for h in hosts):
            platform = plat
            break
    if not platform:
        return None
    path = p.path or "/"
    pattern = SOCIAL_HANDLE_PATTERNS.get(platform)
    if not pattern:
        return None
    m = pattern.match(path)
    if not m:
        return None
    handle = m.group(1).strip().lower()
    if not handle or handle in SOCIAL_PATH_DENYLIST:
        return None
    # YouTube `@` prefix — patterns above strip it but we store with the
    # leading `@` for parity with the platform's user UI when relevant.
    if platform == "TIKTOK":
        handle_out = f"@{handle}"
    else:
        handle_out = handle
    return platform, handle_out


def _looks_like_person_name(s: str) -> bool:
    """Conservative "is this a human name?" heuristic.
    Accepts 2–4 words where each starts with a capital. Rejects strings
    with digits or unusual punctuation.
    """
    s = s.strip().strip(",.:;-—")
    if not s or len(s) > 80:
        return False
    if any(ch.isdigit() for ch in s):
        return False
    words = s.split()
    if not (2 <= len(words) <= 4):
        return False
    for w in words:
        # Allow hyphens (Mary-Jane) and apostrophes (O'Connor).
        clean = w.replace("-", "").replace("'", "")
        if not clean.isalpha():
            return False
        if not clean[0].isupper():
            return False
    return True


def _is_senior_title(s: str) -> bool:
    if not s:
        return False
    sl = s.lower()
    return any(kw in sl for kw in SENIORITY_TITLE_KEYWORDS)


_NAME_TITLE_SEP = re.compile(r"\s+[—–\-,|·•]\s+")


def _extract_name_title_pairs(text_chunks: List[str]) -> List[Tuple[str, str]]:
    """Walk text chunks looking for "Name — Title" pairs in a single chunk,
    or "Name" followed by "Title" in adjacent chunks (the common pattern
    on team cards). Only returns pairs where the title looks senior.
    """
    pairs: List[Tuple[str, str]] = []

    # Pass 1: single-chunk "Name — Title" / "Name, Title" / "Name | Title".
    for chunk in text_chunks:
        if "—" in chunk or "–" in chunk or " - " in chunk or "," in chunk or "|" in chunk:
            parts = _NAME_TITLE_SEP.split(chunk, maxsplit=1)
            if len(parts) == 2:
                name, title = parts[0].strip(), parts[1].strip()
                if _looks_like_person_name(name) and _is_senior_title(title):
                    pairs.append((name, title[:120]))

    # Pass 2: adjacent chunks (heading + paragraph pattern).
    for i in range(len(text_chunks) - 1):
        name = text_chunks[i].strip()
        title = text_chunks[i + 1].strip()
        if _looks_like_person_name(name) and _is_senior_title(title):
            pairs.append((name, title[:120]))

    # Dedupe by lowercased name.
    seen: Dict[str, Tuple[str, str]] = {}
    for n, t in pairs:
        key = n.lower()
        if key not in seen:
            seen[key] = (n, t)
    return list(seen.values())


def _confidence_for_handle(source_path: str, platform: str) -> float:
    """A handle scraped from a page is higher confidence when the source
    is the homepage or footer (the source path is `/`) and lower when it
    comes from a deep page. Common-name guesses get 0.35.
    """
    if source_path == "__guess__":
        return 0.35
    if source_path in ("/", ""):
        return 0.85
    return 0.7


def _confidence_for_vip(title: str) -> float:
    """C-level / president / founder get higher confidence than VP/director."""
    if not title:
        return 0.5
    tl = title.lower()
    if any(k in tl for k in ("ceo", "cto", "cfo", "coo", "ciso", "founder", "president", "chief", "chairman", "owner")):
        return 0.85
    if "vp" in tl or "vice president" in tl:
        return 0.7
    if "director" in tl or "head of" in tl:
        return 0.6
    return 0.55


def _brand_slug_for_guess(brand_name: str, domain: str) -> Optional[str]:
    """Compute a 'common handle' guess from brand name or domain.
    Returns lowercase handle without @, or None if neither yields a
    plausible slug.
    """
    # Try brand name first — collapse whitespace, strip punctuation.
    candidates: List[str] = []
    if brand_name:
        s = re.sub(r"[^A-Za-z0-9]+", "", brand_name).lower()
        if 2 <= len(s) <= 30:
            candidates.append(s)
    # Try domain second — first label only.
    if domain:
        label = _normalize_domain(domain).split(".")[0]
        s = re.sub(r"[^A-Za-z0-9]+", "", label).lower()
        if 2 <= len(s) <= 30 and s not in candidates:
            candidates.append(s)
    return candidates[0] if candidates else None


# ──────────────────────────────────────────────────────────────────
# The tool
# ──────────────────────────────────────────────────────────────────

class BrandDiscoverEntitiesTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "brand:discover_entities"

    @property
    def description(self) -> str:
        return (
            "Scrapes the brand's public website (homepage + common "
            "about/team/press paths) and og:* meta tags to discover "
            "candidate VIPs and social-media handles. Output is fed "
            "into BrandVip / BrandSocialHandle as pending_confirmation "
            "proposals for analyst review."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "brand_monitor_id": {
                    "type": "string",
                    "description": "BrandMonitor.id this discovery targets",
                },
                "brand_name": {
                    "type": "string",
                    "description": "Display name of the brand (for handle-guessing)",
                },
                "domain": {
                    "type": "string",
                    "description": "Apex domain (e.g. acme.com)",
                },
                "websiteUrl": {
                    "type": "string",
                    "description": "Optional full URL of the brand's primary site",
                },
                "tenantId": {
                    "type": "string",
                    "description": "Tenant scoping the discovery (passed through to ingestion)",
                },
            },
            "required": ["brand_monitor_id", "domain"],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "brand",
            "phase": 0,  # auto-dispatched at monitor-create time, before scans
            "domain": ["web", "osint"],
            "input_type": ["domain"],
            "output_type": ["vips", "handles"],
            "chainable_after": [],
            "chainable_before": ["brand:fingerprint_identity"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get("_agent")

        brand_monitor_id = parameters.get("brand_monitor_id") or parameters.get("brandMonitorId") or ""
        brand_name = parameters.get("brand_name") or parameters.get("brandName") or ""
        domain = _normalize_domain(parameters.get("domain") or "")
        website_url = parameters.get("websiteUrl") or parameters.get("website_url")
        tenant_id = parameters.get("tenantId") or parameters.get("tenant_id") or ""

        if not brand_monitor_id:
            return {
                "success": False,
                "error": "brand_monitor_id is required",
                "output": {
                    "vips": [],
                    "handles": [],
                    "brandMonitorId": "",
                    "tenantId": tenant_id,
                    "tool": "brand",
                    "scan_type": "discover_entities",
                },
            }

        if not domain:
            return {
                "success": False,
                "error": "domain is required",
                "output": {
                    "vips": [],
                    "handles": [],
                    "brandMonitorId": brand_monitor_id,
                    "tenantId": tenant_id,
                    "tool": "brand",
                    "scan_type": "discover_entities",
                },
            }

        base_url = _build_base_url(domain, website_url)

        if agent:
            try:
                agent.report_progress(
                    current_operation=f"Discovering entities for {domain}",
                    current_target=base_url,
                    items_processed=0,
                    total_items=len(DISCOVERY_PATHS),
                )
            except Exception:
                pass

        # Aggregators (dedupe later).
        vip_pairs: List[Tuple[str, str, str, float]] = []  # name, title, source_url, conf
        # platform -> { handle: (source_url, confidence) }, keep highest conf.
        handles_seen: Dict[str, Dict[str, Tuple[str, float]]] = {p: {} for p in SOCIAL_HOSTS}

        pages_scanned = 0
        # `_fetch` uses the synchronous `requests` library; calling it
        # directly from this async `execute` would block the event loop for
        # the duration of every HTTP fetch (~10s per stalled page × N paths).
        # The agent runs in a single shared loop with other concurrent
        # workflow steps, so we offload each fetch to the default thread pool
        # via `run_in_executor`. The rest of the parsing is CPU-bound but
        # cheap; leaving it inline keeps the diff minimal.
        loop = asyncio.get_event_loop()
        for idx, path in enumerate(DISCOVERY_PATHS):
            url = urljoin(base_url + "/", path.lstrip("/"))
            html = await loop.run_in_executor(None, _fetch, url)
            if html is None:
                if agent:
                    try:
                        agent.report_progress(
                            current_operation="Scanning",
                            current_target=url,
                            items_processed=idx + 1,
                            total_items=len(DISCOVERY_PATHS),
                        )
                    except Exception:
                        pass
                continue
            pages_scanned += 1

            parser = _DiscoveryParser()
            try:
                parser.feed(html)
            except Exception:
                # Malformed markup — partial parse is fine, just move on.
                pass

            # Extract og:url / twitter:site as a "self" social handle.
            meta_links: List[str] = []
            for key in ("og:url", "twitter:site", "twitter:creator", "al:web:url"):
                v = parser.meta.get(key)
                if v:
                    # twitter:site is sometimes "@handle" — convert to URL form.
                    if key.startswith("twitter:") and v.startswith("@"):
                        meta_links.append(f"https://twitter.com/{v.lstrip('@')}")
                    elif v.startswith("http://") or v.startswith("https://"):
                        meta_links.append(v)

            for href in parser.links + meta_links:
                # Resolve relative + ignore mailto/tel/javascript.
                if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                abs_href = urljoin(url, href)
                hit = _classify_social_link(abs_href)
                if not hit:
                    continue
                platform, handle = hit
                conf = _confidence_for_handle(path, platform)
                existing = handles_seen[platform].get(handle)
                if existing is None or conf > existing[1]:
                    handles_seen[platform][handle] = (abs_href, conf)

            # VIP extraction from this page.
            for name, title in _extract_name_title_pairs(parser.text_chunks):
                vip_pairs.append((name, title, url, _confidence_for_vip(title)))

            if agent:
                try:
                    agent.append_output(
                        f"[BrandDiscoverEntities] {url}: "
                        f"{sum(len(v) for v in handles_seen.values())} handles, "
                        f"{len(vip_pairs)} candidate VIPs so far"
                    )
                    agent.report_progress(
                        current_operation="Scanning",
                        current_target=url,
                        items_processed=idx + 1,
                        total_items=len(DISCOVERY_PATHS),
                    )
                except Exception:
                    pass

        # Add common-name guesses as low-confidence handles for platforms
        # we never saw a real link for. The analyst confirm/reject flow
        # is the authoritative gate.
        guess = _brand_slug_for_guess(brand_name, domain)
        if guess:
            for platform in handles_seen:
                if not handles_seen[platform]:
                    if platform == "TIKTOK":
                        handle = f"@{guess}"
                    else:
                        handle = guess
                    handles_seen[platform][handle] = (
                        "__guess__",
                        _confidence_for_handle("__guess__", platform),
                    )

        # Build output. Dedupe VIPs by lowercased name; prefer the
        # higher-confidence (richer-title) record on collision.
        vip_out: Dict[str, Dict[str, Any]] = {}
        for name, title, source_url, conf in vip_pairs:
            key = name.lower()
            prev = vip_out.get(key)
            if prev is None or conf > prev["confidence"]:
                vip_out[key] = {
                    "name": name,
                    "title": title,
                    "source_url": source_url,
                    "confidence": round(conf, 2),
                }

        handles_out: List[Dict[str, Any]] = []
        for platform, table in handles_seen.items():
            for handle, (source_url, conf) in table.items():
                handles_out.append({
                    "platform": platform,
                    "handle": handle,
                    "source_url": source_url if source_url != "__guess__" else "",
                    "confidence": round(conf, 2),
                })

        result_output = {
            "vips": list(vip_out.values()),
            "handles": handles_out,
            "brandMonitorId": brand_monitor_id,
            "tenantId": tenant_id,
            "pagesScanned": pages_scanned,
            "tool": "brand",
            "scan_type": "discover_entities",
        }

        if agent:
            try:
                agent.append_output(
                    f"[BrandDiscoverEntities] complete: {len(result_output['vips'])} VIPs, "
                    f"{len(result_output['handles'])} handles from {pages_scanned} pages"
                )
            except Exception:
                pass

        return {"success": True, "output": result_output}


def get_tool():
    return BrandDiscoverEntitiesTool()
