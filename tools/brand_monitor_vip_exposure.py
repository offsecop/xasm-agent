"""
Brand VIP exposure monitoring tool.

Uses public search results to look for social profiles, impersonation attempts,
targeting signals, and exposure mentions tied to a registered VIP.
"""

import asyncio
import hashlib
import os
import random
import re
from html import unescape
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp

from plugin_interface import ToolPlugin


PLATFORM_MAP = {
    'linkedin.com': 'LINKEDIN',
    'www.linkedin.com': 'LINKEDIN',
    'x.com': 'X',
    'www.x.com': 'X',
    'twitter.com': 'X',
    'www.twitter.com': 'X',
    'instagram.com': 'INSTAGRAM',
    'www.instagram.com': 'INSTAGRAM',
}

SOCIAL_PROFILE_PATTERNS = {
    'LINKEDIN': [r'/in/', r'/company/'],
    'X': [r'/[A-Za-z0-9_]{2,}$'],
    'INSTAGRAM': [r'/[A-Za-z0-9_.]{2,}$'],
}

DEFAULT_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/122.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
}

EXPOSURE_KEYWORDS = {
    'IMPERSONATION': [
        'impersonat', 'fake account', 'fake profile', 'parody', 'scam profile',
        'clone account', 'fraud account', 'spoof account',
    ],
    # Leak/exposure words are the ONLY HIGH-severity CONTACT_EXPOSURE triggers.
    # Bare contact nouns ('email'/'phone'/etc.) routinely appear on benign
    # "Contact Us" pages and even in our own search queries
    # ("{name} {company} email phone"), so on their own they MUST NOT fire HIGH.
    'CONTACT_EXPOSURE_LEAK': [
        'leak', 'breach', 'dox', 'doxx', 'exposed', 'paste', 'combolist',
        'pastebin',
    ],
    # Bare contact nouns: only count as CONTACT_EXPOSURE (and only MEDIUM) when
    # they co-occur with a leak word above.
    'CONTACT_NOUN': [
        'email', 'phone', 'address', 'contact', 'mobile',
    ],
    'TARGETING_SIGNAL': [
        'target', 'threat', 'harass', 'attack', 'credential', 'phish',
        'extort', 'blackmail', 'swat',
    ],
}


def _normalize_spaces(value: str) -> str:
    return re.sub(r'\s+', ' ', value or '').strip()


def _slug_matches_name(url: str, full_name: str) -> bool:
    lowered_url = (url or '').lower()
    parts = [part for part in re.split(r'[\s\-_.]+', full_name.lower()) if len(part) > 1]
    return bool(parts) and all(part in lowered_url for part in parts[:2])


def _company_tokens(company_name: str, company_domain: str) -> List[str]:
    tokens: List[str] = []
    if company_name:
        tokens.extend(
            [token for token in re.split(r'[\s\-_.]+', company_name.lower()) if len(token) > 2]
        )
    if company_domain:
        root = company_domain.lower().replace('https://', '').replace('http://', '').strip('/')
        root = root.split('/')[0]
        root = root.split(':')[0]
        pieces = [
            piece for piece in root.split('.') if piece and piece not in {'com', 'net', 'org', 'io', 'co'}
        ]
        tokens.extend(pieces[:2])
    return list(dict.fromkeys(tokens))


def _detect_platform(url: str) -> str:
    hostname = (urlparse(url or '').hostname or '').lower()
    for domain, platform in PLATFORM_MAP.items():
        if hostname == domain or hostname.endswith(f'.{domain}'):
            return platform
    return 'WEB'


def _normalize_url(value: str) -> str:
    candidate = _normalize_spaces(value)
    if not candidate:
        return ''
    if not candidate.startswith(('http://', 'https://')):
        candidate = f'https://{candidate}'
    parsed = urlparse(candidate)
    if not parsed.hostname:
        return ''
    return candidate


def _extract_profile_urls(parameters: Dict[str, Any]) -> List[str]:
    urls: List[str] = []
    for key in ['linkedinUrl', 'xUrl', 'twitterUrl', 'instagramUrl', 'websiteUrl']:
        value = parameters.get(key)
        if isinstance(value, str):
            urls.append(value)

    profile_urls = parameters.get('profileUrls')
    if isinstance(profile_urls, list):
        urls.extend([str(value) for value in profile_urls])
    elif isinstance(profile_urls, str):
        urls.extend(profile_urls.split(','))

    normalized = [_normalize_url(value) for value in urls]
    return list(dict.fromkeys([url for url in normalized if url]))


# <title> and <meta> live in <head>; bound the regex scan to the head region so
# the greedy attribute classes can't backtrack across a hostile 200KB body.
_HEAD_SCAN_LIMIT = 65536


def _extract_title(html: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', (html or '')[:_HEAD_SCAN_LIMIT], re.IGNORECASE | re.DOTALL)
    if not match:
        return ''
    return _normalize_spaces(unescape(re.sub(r'<[^>]+>', '', match.group(1))))


def _extract_meta_description(html: str) -> str:
    """Return the <meta name=description> / og:description content, if any."""
    if not html:
        return ''
    html = html[:_HEAD_SCAN_LIMIT]
    for pattern in (
        # name="description" / property="og:description" in either attribute order
        r'<meta[^>]+(?:name|property)\s*=\s*["\'](?:description|og:description)["\'][^>]*\bcontent\s*=\s*["\']([^"\']*)["\']',
        r'<meta[^>]+\bcontent\s*=\s*["\']([^"\']*)["\'][^>]*(?:name|property)\s*=\s*["\'](?:description|og:description)["\']',
    ):
        match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
        if match:
            text = _normalize_spaces(unescape(match.group(1)))
            if text:
                return text
    return ''


def _extract_text_excerpt(html: str, limit: int) -> str:
    """Strip scripts/styles/tags, decode entities, collapse whitespace, and
    return the first `limit` chars of clean visible text. Stdlib-only; never
    throws — returns '' on empty/garbled input."""
    if not html:
        return ''
    try:
        cleaned = re.sub(
            r'<(script|style|noscript)\b[^>]*>.*?</\1>',
            ' ',
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Drop HTML comments, then all remaining tags.
        cleaned = re.sub(r'<!--.*?-->', ' ', cleaned, flags=re.DOTALL)
        cleaned = re.sub(r'<[^>]+>', ' ', cleaned)
        cleaned = unescape(cleaned)
        cleaned = _normalize_spaces(cleaned)
    except Exception:
        return ''
    if limit and limit > 0:
        return cleaned[:limit]
    return cleaned


# Markers that indicate an unauthenticated GET hit a login/consent/block wall
# rather than real profile content (LinkedIn/X/Instagram routinely do this).
#
# Multi-word phrase markers are safe as substring matches — they cannot
# collide with ordinary words. 'access denied' / '403 forbidden' cover real
# block walls without colliding with benign text like "Forbidden City", so the
# bare word 'forbidden' is dropped. The remaining single-word markers
# ('login'/'logon'/'captcha') were previously bare substrings that mis-fired on
# real content ('login' matched "BuabLogin") and suppressed genuine profile
# snippets; they are now matched with word boundaries via a compiled regex.
_LOGIN_WALL_PHRASE_MARKERS = (
    'sign in', 'sign up', 'log in',
    'create an account', 'join now', 'continue with',
    'enable javascript', 'please enable js', 'verify you are human',
    'are you a robot', 'access denied', '403 forbidden',
    'rate limit', 'too many requests', 'page not found',
    'see posts, photos and more', 'something went wrong',
)

_LOGIN_WALL_WORD_RE = re.compile(
    r'\b(?:login|logon|captcha)\b',
    re.IGNORECASE,
)


def _looks_like_login_wall(text: str) -> bool:
    """Heuristic: empty / essentially-no-content, or carries auth/block markers.

    The length floor is deliberately low (24): a short-but-real snippet like
    "Reported transactions: 12,000 shares" is legitimate content, not a wall.
    Walls are caught by the marker list, not by being merely terse."""
    snippet = (text or '').strip()
    if len(snippet) < 24:
        return True
    lowered = snippet.lower()
    if any(marker in lowered for marker in _LOGIN_WALL_PHRASE_MARKERS):
        return True
    return bool(_LOGIN_WALL_WORD_RE.search(snippet))


def _strip_html(value: str) -> str:
    return _normalize_spaces(unescape(re.sub(r'<[^>]+>', ' ', value or '')))


def _unwrap_search_url(url: str) -> str:
    candidate = unescape(url or '').strip()
    if candidate.startswith('//'):
        candidate = f'https:{candidate}'

    parsed = urlparse(candidate)
    if parsed.hostname and parsed.hostname.endswith('duckduckgo.com') and parsed.path.startswith('/l/'):
        target = parse_qs(parsed.query).get('uddg', [''])[0]
        if target:
            return unquote(target)

    return candidate


def _parse_duckduckgo_html(html: str, max_results: int) -> List[Dict[str, str]]:
    """Parse DuckDuckGo HTML-endpoint results into {url, title, content}.

    Robust to DDG's nested-div markup: rather than carving fixed result "blocks"
    (the previous `</div></div>` boundary truncated BEFORE the snippet, so
    `content` came back empty), we locate each result link and take its snippet
    from the segment running up to the NEXT result link. The snippet terminator
    is tolerant of </a>, </div>, or </span> (DDG has used each)."""
    html = html or ''
    results: List[Dict[str, str]] = []
    links = list(re.finditer(
        r'<a[^>]+class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        html,
        flags=re.IGNORECASE | re.DOTALL,
    ))
    for i, link in enumerate(links):
        seg_start = link.end()
        seg_end = links[i + 1].start() if i + 1 < len(links) else len(html)
        segment = html[seg_start:seg_end]
        snippet_match = re.search(
            r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</(?:a|div|span)>',
            segment,
            flags=re.IGNORECASE | re.DOTALL,
        )
        url = _unwrap_search_url(link.group(1))
        if not url:
            continue
        results.append({
            'url': url,
            'title': _strip_html(link.group(2)),
            'content': _strip_html(snippet_match.group(1) if snippet_match else ''),
        })
        if len(results) >= max_results:
            break

    return results


def _profile_finding(
    brand_vip_id: str,
    profile_url: str,
    full_name: str,
    company_name: str,
    company_domain: str,
    title: str,
    validation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    platform = _detect_platform(profile_url)
    finding_hash = hashlib.sha256(
        f"{brand_vip_id}|{profile_url}|known-profile".encode('utf-8')
    ).hexdigest()
    validated = bool(validation and validation.get('reachable'))
    page_title = validation.get('title') if validation else ''
    source_name = platform.title() if platform != 'WEB' else 'Known Web Profile'

    # Prefer a real excerpt extracted from the fetched body: meta-description
    # first, then visible-text excerpt. Social profiles frequently return a
    # login/consent wall to unauthenticated GETs — when the extracted content
    # is empty or looks like such a wall, fall back to an honest, concise
    # snippet instead of fabricating page content.
    meta_description = (validation or {}).get('metaDescription') or ''
    text_excerpt = (validation or {}).get('textExcerpt') or ''
    content_source = ''
    if meta_description and not _looks_like_login_wall(meta_description):
        content_snippet = meta_description
        content_source = 'metaDescription'
    elif text_excerpt and not _looks_like_login_wall(text_excerpt):
        content_snippet = text_excerpt
        content_source = 'textExcerpt'
    elif validated:
        content_snippet = (
            f'Profile page for {full_name} is reachable; full content requires '
            f'an authenticated capture (unauthenticated request returned a '
            f'login wall or minimal markup).'
        )
        content_source = 'login-wall-fallback'
    else:
        content_snippet = (
            f'{full_name} has a registered public profile URL that can be tracked '
            f'for impersonation, account changes, and exposure signals.'
        )
        content_source = 'unreachable-fallback'

    excerpt_chars = len(content_snippet)

    return {
        'findingHash': finding_hash,
        'platform': platform,
        'sourceName': source_name,
        'sourceUrl': profile_url,
        'title': page_title or f'Known {source_name} profile for {full_name}',
        'contentSnippet': content_snippet,
        'exposureType': 'SOCIAL_PROFILE' if platform != 'WEB' else 'PUBLIC_PROFILE',
        'severity': 'LOW',
        'riskScore': 30 if validated else 24,
        'confidenceScore': 0.99 if validated else 0.92,
        'status': 'NEW',
        'matchedKeywords': [token for token in [full_name, company_name or company_domain, title] if token],
        'discoveredAt': datetime.now(timezone.utc).isoformat(),
        'metadata': {
            'engine': 'direct-profile',
            'seededFromInput': True,
            'validated': validated,
            'httpStatus': validation.get('httpStatus') if validation else None,
            'finalUrl': validation.get('finalUrl') if validation else profile_url,
            'contentType': validation.get('contentType') if validation else None,
            'metaDescription': meta_description or None,
            'excerptChars': excerpt_chars,
            'contentSource': content_source,
        },
    }


async def _fetch_and_extract(session, url: str, excerpt_limit: int = 1500) -> Dict[str, Any]:
    """GET `url` and pull title / meta-description / text-excerpt from HTML.

    Content-type-guarded (non-HTML bodies like PDF/JSON/image are NOT regex-fed),
    body capped at 200KB, never throws. Used by BOTH the seeded-profile path and
    the public-search path so a discovered page (e.g. a data-broker / news page
    found via search) carries its real content, not just a link + blurb."""
    try:
        async with session.get(url, allow_redirects=True) as resp:
            content_type = (resp.headers.get('Content-Type') or '').lower()
            is_markup = 'html' in content_type or 'xml' in content_type or not content_type
            capped_body = (await resp.text(errors='ignore'))[:200000] if is_markup else ''
            return {
                'reachable': 200 <= resp.status < 400,
                'httpStatus': resp.status,
                'finalUrl': str(resp.url),
                'contentType': content_type or None,
                'title': _extract_title(capped_body),
                'metaDescription': _extract_meta_description(capped_body),
                'textExcerpt': _extract_text_excerpt(capped_body, excerpt_limit),
            }
    except Exception as exc:
        return {
            'reachable': False,
            'error': str(exc),
            'finalUrl': url,
            'title': '',
            'metaDescription': '',
            'textExcerpt': '',
        }


def _best_extracted_content(extracted: Dict[str, Any], fallback: str = '') -> tuple:
    """Pick the best human-readable content from a `_fetch_and_extract` result:
    meta-description, else text excerpt, else the supplied fallback (e.g. the
    search-result blurb). Returns (content, source_label)."""
    meta = (extracted.get('metaDescription') or '').strip()
    if meta and not _looks_like_login_wall(meta):
        return meta, 'metaDescription'
    excerpt = (extracted.get('textExcerpt') or '').strip()
    if excerpt and not _looks_like_login_wall(excerpt):
        return excerpt, 'textExcerpt'
    fb = (fallback or '').strip()
    if fb:
        return fb, 'searchBlurb'
    return '', 'none'


def _classify_exposure(
    platform: str,
    title: str,
    snippet: str,
    url: str,
    full_name: str,
    company_name: str,
    company_domain: str,
) -> Dict[str, Any]:
    # Identity matching may use the URL — a name/company legitimately lives in a
    # slug. Exposure CLASSIFICATION must NOT: a benign URL containing
    # 'paste'/'exposed'/'fake' (e.g. /exposed-beams-listing) would otherwise
    # over-fire HIGH severity. So the keyword scans below run against page
    # CONTENT (title + snippet) only, never the URL.
    identity_haystack = _normalize_spaces(f"{title} {snippet} {url}").lower()
    haystack = _normalize_spaces(f"{title} {snippet}").lower()
    exact_name = full_name.lower() in identity_haystack
    company_match = False
    for token in _company_tokens(company_name, company_domain):
        if token in identity_haystack:
            company_match = True
            break

    if not exact_name and not _slug_matches_name(url, full_name):
        return {}

    exposure_type = 'SOCIAL_MENTION' if platform != 'WEB' else 'PUBLIC_MENTION'
    severity = 'LOW'
    risk_score = 32
    confidence = 0.45

    if platform in SOCIAL_PROFILE_PATTERNS:
        if any(re.search(pattern, urlparse(url).path or '', re.IGNORECASE) for pattern in SOCIAL_PROFILE_PATTERNS[platform]):
            exposure_type = 'SOCIAL_PROFILE'
            severity = 'LOW'
            risk_score = 28
            confidence = 0.62

    for keyword in EXPOSURE_KEYWORDS['IMPERSONATION']:
        if keyword in haystack:
            exposure_type = 'IMPERSONATION'
            severity = 'HIGH'
            risk_score = 82
            confidence = 0.88
            break

    if exposure_type not in {'IMPERSONATION'}:
        has_leak_word = any(
            keyword in haystack for keyword in EXPOSURE_KEYWORDS['CONTACT_EXPOSURE_LEAK']
        )
        has_contact_noun = any(
            keyword in haystack for keyword in EXPOSURE_KEYWORDS['CONTACT_NOUN']
        )
        if has_leak_word:
            # Genuine leak/breach/dox/paste signal — HIGH.
            exposure_type = 'CONTACT_EXPOSURE'
            severity = 'HIGH'
            risk_score = 78
            confidence = 0.8
        elif has_contact_noun:
            # A bare contact noun with no leak word: a "Contact Us" page or a
            # bio that lists an email is not a HIGH exposure. Cap at MEDIUM.
            exposure_type = 'CONTACT_EXPOSURE'
            severity = 'MEDIUM'
            risk_score = 52
            confidence = 0.55

    if exposure_type not in {'IMPERSONATION', 'CONTACT_EXPOSURE'}:
        for keyword in EXPOSURE_KEYWORDS['TARGETING_SIGNAL']:
            if keyword in haystack:
                exposure_type = 'TARGETING_SIGNAL'
                severity = 'MEDIUM' if platform == 'WEB' else 'HIGH'
                risk_score = 72 if platform != 'WEB' else 64
                confidence = 0.74
                break

    if company_match:
        confidence += 0.12
        risk_score += 8

    if platform != 'WEB':
        confidence += 0.08

    return {
        'exposureType': exposure_type,
        'severity': severity,
        'riskScore': min(risk_score, 95),
        'confidenceScore': round(min(confidence, 0.99), 2),
        'companyMatched': company_match,
        'exactNameMatched': exact_name,
    }


class BrandMonitorVipExposureTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "brand:monitor_vip_exposure"

    @property
    def description(self) -> str:
        return (
            "Search public web and social profile results for a registered VIP to find "
            "profiles, mentions, targeting signals, and impersonation exposure."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "brandVipId": {
                    "type": "string",
                    "description": "Registered VIP identifier",
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor identifier",
                },
                "companyName": {
                    "type": "string",
                    "description": "Company name for contextual matching",
                },
                "companyDomain": {
                    "type": "string",
                    "description": "Company domain for contextual matching",
                },
                "fullName": {
                    "type": "string",
                    "description": "VIP full name",
                },
                "title": {
                    "type": "string",
                    "description": "VIP title or role",
                },
                "email": {
                    "type": "string",
                    "description": "VIP email if known",
                },
                "linkedinUrl": {
                    "type": "string",
                    "description": "Known LinkedIn URL if already captured",
                },
                "profileUrls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Known public profile URLs such as LinkedIn, X, Instagram, or personal bio pages",
                },
                "maxResults": {
                    "type": "integer",
                    "description": "Maximum number of findings to return",
                    "default": 15,
                },
            },
            "required": ["brandVipId", "brandMonitorId", "fullName"],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "brand",
            "phase": 4,
            "domain": ["osint", "drp"],
            "input_type": ["person"],
            "output_type": ["vip_exposures"],
            "chainable_after": ["brand:discover_vips"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')
        brand_vip_id = parameters.get('brandVipId')
        brand_monitor_id = parameters.get('brandMonitorId')
        full_name = _normalize_spaces(parameters.get('fullName', ''))
        company_name = _normalize_spaces(parameters.get('companyName', ''))
        company_domain = _normalize_spaces(parameters.get('companyDomain', ''))
        title = _normalize_spaces(parameters.get('title', ''))
        profile_urls = _extract_profile_urls(parameters)
        max_results = int(parameters.get('maxResults', 15) or 15)

        # 2026-05-16 — SearxNG decommissioned. The block that used to query
        # SEARXNG_URL for VIP-exposure mentions has been removed; the
        # direct-profile-check path + public-search path (handled below)
        # remain as the only sources for VIP exposure findings.

        if not brand_vip_id or not brand_monitor_id or not full_name:
            return {
                'success': False,
                'error': 'brandVipId, brandMonitorId, and fullName are required',
                'output': {
                    'brandVipId': brand_vip_id,
                    'brandMonitorId': brand_monitor_id,
                    'findings': [],
                    'queriesRun': 0,
                },
            }

        company_hint = company_name or company_domain

        findings: List[Dict[str, Any]] = []
        seen_hashes = set()
        # DDG HTML scraping is OFF by default (explicit opt-in only). It is a
        # generic web-search source — the same category as SearxNG (fully
        # decommissioned 2026-05-16) and Brave/SerpAPI/Tavily (deferred per the
        # locked DRP vendor scope: only HIKER_API / SCRAPECREATORS /
        # TWITTERAPI_IO are in scope). It was never a sanctioned vendor (it's an
        # uncredentialed scrape with ToS/ban exposure), so it stays disabled
        # until a real search vendor is wired; flip VIP_EXPOSURE_PUBLIC_SEARCH=true
        # only to re-enable the stopgap deliberately. The extraction code below
        # is kept intact (dormant) for that future sanctioned source.
        public_search_configured = (
            os.environ.get('VIP_EXPOSURE_PUBLIC_SEARCH', 'false').lower() == 'true'
        )
        search_diagnostics = {
            'publicSearchConfigured': public_search_configured,
            'publicSearchQueriesRun': 0,
            'publicSearchResultsSeen': 0,
            'publicSearchFailedQueries': 0,
        }

        # The DDG public-search path builds its own query list. Compute it up
        # front so progress + the result envelope can report the REAL number of
        # search queries that will actually run (no dead/imaginary query count).
        public_queries: List[str] = []
        if public_search_configured:
            public_queries = list(dict.fromkeys([
                query for query in (
                    f'{full_name} {company_hint}'.strip(),
                    f'{full_name} {company_hint} linkedin'.strip(),
                    f'{full_name} {company_hint} email phone'.strip(),
                ) if query
            ]))[:3]

        if agent:
            agent.report_progress(
                current_operation=f"Monitoring exposure for {full_name}",
                current_target=company_hint or full_name,
                items_processed=0,
                total_items=len(profile_urls) + len(public_queries),
            )

        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout, headers=DEFAULT_HEADERS) as session:
            for profile_url in profile_urls:
                # Content-type-guarded fetch + HTML extraction (shared with the
                # public-search path below).
                validation = await _fetch_and_extract(session, profile_url)

                finding = _profile_finding(
                    brand_vip_id,
                    profile_url,
                    full_name,
                    company_name,
                    company_domain,
                    title,
                    validation,
                )
                seen_hashes.add(finding['findingHash'])
                findings.append(finding)

            if public_queries:
                # Budget for fetching discovered result pages (to extract real
                # content vs. just the DDG blurb). Bounded so a query with many
                # hits can't fan out unbounded fetches / latency.
                pages_fetched = 0
                max_page_fetches = 8
                # B11 — DDG ban-avoidance hardening. The 0.35s inter-query sleep
                # used previously was below DDG's empirical anti-bot threshold;
                # we now jitter 2–5s between requests. DDG is intentionally NOT
                # routed through `checkout_provider()` because it is an
                # uncredentialed HTML scrape; the DRP vendor scope (locked
                # 2026-05-15 in feedback_drp_vendor_scope.md) admits only
                # HIKER_API / SCRAPECREATORS / TWITTERAPI_IO. Adding
                # DUCKDUCKGO_SEARCH to the IntegrationProvider enum would
                # require schema migration + Integration row + plan quota and
                # contradicts the "no new vendors" rule.
                for query in public_queries:
                    try:
                        search_diagnostics['publicSearchQueriesRun'] += 1
                        async with session.get(
                            'https://html.duckduckgo.com/html/',
                            params={'q': query},
                        ) as resp:
                            # Honor Retry-After on 429 / 202 (DDG sometimes
                            # returns a soft-rate-limit 202 with the same
                            # header semantics as 429). Cap the wait at 10s
                            # so a malicious / runaway header can't pin us.
                            if resp.status in (202, 429):
                                retry_after_header = resp.headers.get('Retry-After')
                                wait_s = 5.0
                                if retry_after_header:
                                    try:
                                        wait_s = min(float(retry_after_header), 10.0)
                                    except (ValueError, TypeError):
                                        pass
                                search_diagnostics['publicSearchFailedQueries'] += 1
                                if agent:
                                    agent.append_output(
                                        f"[VipExposure] DDG rate-limit HTTP {resp.status} "
                                        f"on query '{query}', backing off {wait_s:.1f}s"
                                    )
                                await asyncio.sleep(wait_s)
                                continue
                            if resp.status != 200:
                                search_diagnostics['publicSearchFailedQueries'] += 1
                                continue
                            # Cap the DDG body before parsing (parity with the
                            # 200KB profile-body cap) so a pathological page
                            # can't pin the regex parser.
                            html = (await resp.text(errors='ignore'))[:500000]
                    except Exception as exc:
                        search_diagnostics['publicSearchFailedQueries'] += 1
                        if agent:
                            agent.append_output(f"[VipExposure] Public search failed for query '{query}': {exc}")
                        continue

                    public_results = _parse_duckduckgo_html(html, 8)
                    search_diagnostics['publicSearchResultsSeen'] += len(public_results)
                    for item in public_results:
                        source_url = item.get('url', '') or ''
                        title_text = item.get('title', '') or ''
                        snippet = item.get('content', '') or ''
                        platform = _detect_platform(source_url)
                        classification = _classify_exposure(
                            platform,
                            title_text,
                            snippet,
                            source_url,
                            full_name,
                            company_name,
                            company_domain,
                        )
                        if not classification:
                            continue

                        finding_hash = hashlib.sha256(
                            f"{brand_vip_id}|{source_url}|{classification['exposureType']}".encode('utf-8')
                        ).hexdigest()
                        if finding_hash in seen_hashes:
                            continue
                        seen_hashes.add(finding_hash)

                        # Fetch the DISCOVERED page and extract its real content
                        # — the DDG result blurb is frequently empty/thin (that's
                        # the "Public Web Search finding shows only a link" gap).
                        # Falls back to the blurb, then to nothing. Bounded by the
                        # per-run fetch budget. Same uncredentialed direct GET as
                        # the profile path (no new vendor).
                        content = snippet
                        content_source = 'searchBlurb' if snippet else 'none'
                        page_meta: Dict[str, Any] = {}
                        if pages_fetched < max_page_fetches:
                            pages_fetched += 1
                            extracted = await _fetch_and_extract(session, source_url)
                            content, content_source = _best_extracted_content(extracted, snippet)
                            page_meta = {
                                'pageHttpStatus': extracted.get('httpStatus'),
                                'pageContentType': extracted.get('contentType'),
                                'pageReachable': extracted.get('reachable'),
                            }

                        findings.append({
                            'findingHash': finding_hash,
                            'platform': platform,
                            'sourceName': platform.title() if platform != 'WEB' else 'Public Web Search',
                            'sourceUrl': source_url,
                            'title': title_text or f'Public result for {full_name}',
                            'contentSnippet': content[:1500],
                            'exposureType': classification['exposureType'],
                            'severity': classification['severity'],
                            'riskScore': classification['riskScore'],
                            'confidenceScore': classification['confidenceScore'],
                            'status': 'NEW',
                            'matchedKeywords': [token for token in [full_name, company_name or company_domain, title] if token],
                            'discoveredAt': datetime.now(timezone.utc).isoformat(),
                            'metadata': {
                                'query': query,
                                'companyMatched': classification['companyMatched'],
                                'exactNameMatched': classification['exactNameMatched'],
                                'engine': 'duckduckgo-html',
                                'contentSource': content_source,
                                # Full extracted/blurb content (capped at 4000 so
                                # a pathological page can't bloat the row); the
                                # 1500-char contentSnippet is the display copy.
                                'fullContent': content[:4000],
                                'excerptChars': len(content[:1500]),
                                **page_meta,
                            },
                        })

                    # Jittered inter-query backoff (2–5s) — stays below DDG's
                    # empirical anti-bot trigger while still making forward
                    # progress on the 3-query budget.
                    await asyncio.sleep(random.uniform(2.0, 5.0))

        # Always retain the reliable seeded profile findings regardless of the
        # cap — sorting by (riskScore, confidence) desc could otherwise drop
        # them under a flood of high-risk search hits. Fill the remaining slots
        # with the top search findings.
        seeded = [
            finding for finding in findings
            if (finding.get('metadata') or {}).get('seededFromInput') is True
        ]
        searched = [
            finding for finding in findings
            if (finding.get('metadata') or {}).get('seededFromInput') is not True
        ]
        searched.sort(key=lambda item: (item['riskScore'], item['confidenceScore']), reverse=True)
        remaining_slots = max(max_results - len(seeded), 0)
        findings = seeded + searched[:remaining_slots]

        # queriesRun reports the REAL number of public searches that ran (the
        # DDG public-search path is the only query source after SearxNG was
        # decommissioned). No imaginary/dead query count.
        queries_run = search_diagnostics['publicSearchQueriesRun']

        if agent:
            agent.append_output(
                f"[VipExposure] {full_name}: collected {len(findings)} finding(s) "
                f"from {queries_run} public search query(ies)"
            )

        return {
            'success': True,
            'output': {
                'brandVipId': brand_vip_id,
                'brandMonitorId': brand_monitor_id,
                'fullName': full_name,
                'findings': findings,
                'queriesRun': queries_run,
                'searchDiagnostics': search_diagnostics,
            },
        }


def get_tool():
    return BrandMonitorVipExposureTool()
