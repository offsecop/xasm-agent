"""
Dark Web Monitor Tool
Queries OSINT sources and threat intelligence feeds for dark web mentions,
credential leaks, phishing kit sales, and brand targeting discussions.
"""

import sys
import asyncio
import aiohttp
import json
import logging
import os
import re
import time
import hashlib
import shutil
import subprocess
import tempfile
import urllib.parse
from datetime import datetime
from math import log2
from typing import Dict, Any, List, Optional
from pathlib import Path
from html import unescape

logger = logging.getLogger(__name__)


def _plain_term_matches(term: str, haystack: str) -> bool:
    """TOKEN-BOUNDARY containment for a non-regex search term.

    The legacy gate used ``term.lower() in haystack`` (bare substring), which
    fired on unrelated text: a short brand acronym landing INSIDE an unrelated
    word (a 3-letter term inside a longer one) or a brand landing inside a glued
    phrase (two adjacent words concatenated). We instead require the term to
    appear on WORD boundaries, so a whole-word / domain match still hits while an
    arbitrary infix does not. Falls back to plain containment only if the
    boundary regex cannot be built (never less strict on the common path)."""
    term = (term or '').strip().lower()
    if not term:
        return False
    hay = (haystack or '').lower()
    try:
        return re.search(r'(?<![0-9a-z])' + re.escape(term) + r'(?![0-9a-z])', hay) is not None
    except re.error:
        return term in hay


# Ensure agent/ is on sys.path so `from lib.integration_credentials import ...`
# works when the plugin is loaded via spec_from_file_location.
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

from plugin_interface import ToolPlugin
from lib.integration_credentials import (  # noqa: E402
    checkout_provider,
    reconcile_call,
    upstream_request,
    QuotaExceededError,
    IntegrationCredentialsError,
)
from lib.serper_search import (  # noqa: E402
    dispatch_serper,
    SerpNotConfigured,
    SerpSweepFailed,
)

try:
    from playwright.async_api import async_playwright
except Exception:
    async_playwright = None

from lib.process_reaper import close_browser_safe, register_group


# OTX and IntelX are out of the DRP migration vendor scope (locked-decision
# #5; only HikerAPI / ScrapeCreators / twitterapi.io are in scope). The
# integrations stay in the codebase for non-DRP use cases but default OFF —
# operators must set ENABLE_OTX=true / ENABLE_INTELX=true explicitly to
# re-enable. With the flag off, _query_otx / _query_intelx short-circuit to
# an empty result list before any HTTP work (so no leases consumed, no
# vendor calls).
ENABLE_OTX = os.environ.get("ENABLE_OTX", "false").lower() in ("true", "1", "yes")
ENABLE_INTELX = os.environ.get("ENABLE_INTELX", "false").lower() in ("true", "1", "yes")


# #1611 — Phishing.Database ACTIVE-domains feed. A FREE, KEYLESS, MIT-licensed
# global feed (mitchellkrogza/Phishing.Database) of community-verified ACTIVE
# phishing domains, regenerated ~every 2h. Like the RansomLook leg it is a free
# GLOBAL feed matched per-tenant in-process (NOT a per-tenant paid vendor), so
# it leases NO ProviderQuotaService slot and needs no IntegrationProvider enum.
# Cached process-wide with a TTL + conditional GET (ETag) so the five agent
# containers do not re-pull ~11 MB on every scan.
_PHISHING_DB_URL = (
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
    "master/phishing-domains-ACTIVE.txt"
)
_PHISHING_DB_TTL_SECONDS = 2 * 60 * 60  # matches the feed's ~2h regen cadence
# Process-wide cache: the parsed set of active phishing domains + the ETag for
# conditional GETs. Guarded by a lazily-created asyncio.Lock (created inside a
# running loop so no event-loop is bound at import time).
_phishing_db_cache: Dict[str, Any] = {"fetched_at": 0.0, "etag": None, "domains": None}
_phishing_db_lock: Optional["asyncio.Lock"] = None


def _get_phishing_db_lock() -> "asyncio.Lock":
    global _phishing_db_lock
    if _phishing_db_lock is None:
        _phishing_db_lock = asyncio.Lock()
    return _phishing_db_lock


# #1617 — cap on emitted rows per scan. A cap is NOT an FP control (the gate
# below is); it is a blast-radius bound. Exceeding it is reported, never
# silently swallowed — see `swept_truncated`.
PHISHING_DB_MAX_EMISSIONS = 25


def _match_phishing_domains(
    phishing_domains: Any, term_set: Any
) -> List[tuple]:
    """Boundary-anchored brand match against the Phishing.Database feed.

    #1617 — extracted as a MODULE-LEVEL PURE function so the FP gate is
    directly unit-testable (`agent/tests/test_phishing_database_gate.py`).
    The original gate lived inline in an async method behind a network fetch,
    so the only "coverage" it had was a backend replay cassette injected
    DOWNSTREAM of this code — which could not reach it, and passed with the
    gate deleted.

    A term matches only when it EQUALS a whole `-`-delimited segment of a
    `.`-delimited label of the REGISTRABLE NAME. The public suffix is excluded:
    splitting the full domain made every `.cloud` / `.shop` / `.link` phishing
    domain a hit for a same-named term (measured on the live 391,616-row feed:
    `link` 6,667 hits of which 6,338 TLD-only, `site` 4,928/4,081,
    `shop` 3,313/3,077). Substring matching is ALWAYS wrong here — raw
    substring `trade` = 316 hits vs 6 boundary-gated.

    Returns (domain, matched_term) pairs sorted by domain for determinism.
    """
    matched_pairs: List[tuple] = []
    for pd in phishing_domains:
        labels = str(pd).strip().lower().split(".")
        if len(labels) < 2:
            # No public suffix → not a resolvable domain; skip rather than
            # match against a bare token.
            continue
        # Drop the TLD. Everything left is the registrable name + subdomains,
        # which is the only region a brand can legitimately be impersonated in.
        segments = [seg for label in labels[:-1] for seg in label.split("-")]
        hit = next((t for t in segments if t in term_set), None)
        if hit is not None:
            matched_pairs.append((pd, hit))
    matched_pairs.sort(key=lambda p: p[0])
    return matched_pairs


class DarkWebMonitorTool(ToolPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Per-scan feed sweep status (FEED-2/HONESTY-1). execute() resets this
        # at scan start — that stays the single reset point. Initialising it
        # here means a leg invoked directly (Layer-A locks, and any future
        # non-execute() caller) records its status instead of AttributeError-ing
        # inside its own broad `except`, which would re-open the exact
        # silent-failure hole the status field exists to close.
        self._source_status: Dict[str, str] = {}

    def _get_env_int(self, name: str, default: int, minimum: int = 1, maximum: Optional[int] = None) -> int:
        raw_value = os.environ.get(name, '').strip()
        if not raw_value:
            return default

        try:
            parsed = int(raw_value)
        except ValueError:
            return default

        parsed = max(minimum, parsed)
        if maximum is not None:
            parsed = min(parsed, maximum)
        return parsed

    @property
    def name(self) -> str:
        return "darkweb:monitor"

    @property
    def description(self) -> str:
        return "Monitor dark web sources, paste sites, and threat intelligence feeds for brand mentions, credential leaks, phishing kit sales, and targeting discussions"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to monitor (e.g., example.com)"
                },
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional keywords to search for"
                },
                "patterns": {
                    "type": "array",
                    "items": {
                        "oneOf": [
                            {"type": "string"},
                            {
                                "type": "object",
                                "properties": {
                                    "id": {"type": "string"},
                                    "name": {"type": "string"},
                                    "pattern": {"type": "string"},
                                    "isRegex": {"type": "boolean"},
                                    "sources": {
                                        "type": "array",
                                        "items": {"type": "string"}
                                    }
                                }
                            }
                        ]
                    },
                    "description": "Structured data leak patterns associated with the brand monitor"
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor ID for result correlation"
                },
                "dorkCohort": {
                    "type": "integer",
                    "description": "GitHub dork rotation cursor (#436). Selects which dork cohort runs this scan cycle (cohort = dorkCohort % NUM_COHORTS). Threaded from the backend orchestrator's MonitorEngineState.runCount; when absent a stateless wall-clock fallback rotates deterministically."
                },
                "extraDomains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Owned/defensive domains (#889) to sweep for credential/breach exposure IN ADDITION to the primary `domain` apex. The credential legs (LeakCheck, HIBP) probe each of these too, so a report's 'N owned domains protected' claim is true instead of covering only the monitor apex. Backend-supplied: already tenant-scoped, deduped, capped, and rotated per scan cycle (the agent sweeps exactly what it receives)."
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Sources to query (default: all). Options: urlhaus, otx, github, gitlab, bitbucket, npm, stackoverflow, pastebin, leakcheck, threatfox, ransomware_leaksites, phishing_database, hibp, intelx, onion_forums, simulation"
                },
                "maxResults": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100)"
                }
            },
            "required": ["domain"]
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "recon",
            "phase": 1,
            "domain": ["osint", "darkweb"],
            "input_type": ["domain"],
            "output_type": ["darkweb_mentions"],
            "chainable_after": ["typosquat:detect"],
            "chainable_before": [],
        }

    def _normalize_patterns(self, keywords: List[str], patterns: Any) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        seen = set()

        def add_pattern(entry: Dict[str, Any]) -> None:
            pattern = str(entry.get('pattern') or '').strip()
            if not pattern:
                return

            normalized_entry = {
                'id': entry.get('id'),
                'name': str(entry.get('name') or pattern).strip(),
                'pattern': pattern,
                'isRegex': bool(entry.get('isRegex', False)),
                'sources': [str(source).upper() for source in (entry.get('sources') or []) if str(source).strip()],
            }

            key = (
                normalized_entry['pattern'].lower(),
                normalized_entry['isRegex'],
                tuple(sorted(normalized_entry['sources'])),
            )
            if key in seen:
                return

            seen.add(key)
            normalized.append(normalized_entry)

        for keyword in keywords or []:
            if isinstance(keyword, str) and keyword.strip():
                add_pattern({
                    'name': keyword.strip(),
                    'pattern': keyword.strip(),
                    'isRegex': False,
                    'sources': [],
                })

        for raw in patterns or []:
            if isinstance(raw, str):
                add_pattern({
                    'name': raw.strip(),
                    'pattern': raw.strip(),
                    'isRegex': False,
                    'sources': [],
                })
            elif isinstance(raw, dict):
                add_pattern(raw)

        return normalized

    def _get_darkweb_settings(self, agent=None) -> Dict[str, Any]:
        config = {}
        if agent and isinstance(getattr(agent, 'config', None), dict):
            config = agent.config.get('darkweb', {}) or {}

        def get_str(name: str, config_key: str, default: str = '') -> str:
            value = os.environ.get(name)
            if value is not None and str(value).strip():
                return str(value).strip()
            cfg_value = config.get(config_key)
            return str(cfg_value).strip() if cfg_value is not None and str(cfg_value).strip() else default

        def get_bool(name: str, config_key: str, default: bool = False) -> bool:
            value = os.environ.get(name)
            if value is not None and str(value).strip():
                return str(value).strip().lower() in ('1', 'true', 'yes', 'on')
            cfg_value = config.get(config_key)
            if isinstance(cfg_value, bool):
                return cfg_value
            if cfg_value is not None and str(cfg_value).strip():
                return str(cfg_value).strip().lower() in ('1', 'true', 'yes', 'on')
            return default

        def get_int(name: str, config_key: str, default: int, minimum: int = 1, maximum: Optional[int] = None) -> int:
            env_value = os.environ.get(name)
            if env_value is not None and str(env_value).strip():
                try:
                    parsed = int(env_value)
                except ValueError:
                    parsed = default
            else:
                cfg_value = config.get(config_key)
                try:
                    parsed = int(cfg_value) if cfg_value is not None else default
                except (ValueError, TypeError):
                    parsed = default

            parsed = max(minimum, parsed)
            if maximum is not None:
                parsed = min(parsed, maximum)
            return parsed

        return {
            'tor_proxy_url': get_str('DARKWEB_TOR_PROXY_URL', 'tor_proxy_url'),
            'enable_onion_sources': get_bool('DARKWEB_ENABLE_ONION_SOURCES', 'enable_onion_sources', False),
            'onion_sources_file': get_str('DARKWEB_ONION_SOURCES_FILE', 'onion_sources_file'),
            'onion_sources_json': get_str('DARKWEB_ONION_SOURCES_JSON', 'onion_sources_json'),
            'onion_use_browser': get_bool('DARKWEB_ONION_USE_BROWSER', 'onion_use_browser', False),
            'onion_fetch_timeout_seconds': get_int('DARKWEB_ONION_FETCH_TIMEOUT_SECONDS', 'onion_fetch_timeout_seconds', 45, minimum=5, maximum=180),
            'onion_max_sources': get_int('DARKWEB_ONION_MAX_SOURCES', 'onion_max_sources', 8, minimum=1, maximum=30),
            'onion_max_pages_per_source': get_int('DARKWEB_ONION_MAX_PAGES_PER_SOURCE', 'onion_max_pages_per_source', 3, minimum=1, maximum=10),
            'onion_terms_per_source': get_int('DARKWEB_ONION_TERMS_PER_SOURCE', 'onion_terms_per_source', 2, minimum=1, maximum=6),
        }

    def _resolve_data_path(self, value: str) -> Optional[Path]:
        if not value:
            return None

        expanded = Path(os.path.expanduser(value))
        if expanded.is_absolute():
            return expanded

        candidates = [
            Path.cwd() / expanded,
            Path(__file__).resolve().parent / expanded,
            Path(__file__).resolve().parent.parent / expanded,
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0]

    def _load_onion_sources(self, settings: Dict[str, Any], agent=None) -> List[Dict[str, Any]]:
        raw_sources = settings.get('onion_sources_json', '').strip()
        payload: Any = None

        if raw_sources:
            try:
                payload = json.loads(raw_sources)
            except json.JSONDecodeError as error:
                if agent:
                    agent.report_progress(f"Invalid DARKWEB_ONION_SOURCES_JSON: {error}")
                return []
        else:
            source_file = self._resolve_data_path(settings.get('onion_sources_file', ''))
            if not source_file or not source_file.exists():
                if agent:
                    agent.report_progress("No onion source catalog configured, skipping onion forum crawl")
                return []
            try:
                with source_file.open('r') as handle:
                    payload = json.load(handle)
            except Exception as error:
                if agent:
                    agent.report_progress(f"Failed to load onion source catalog: {error}")
                return []

        if isinstance(payload, dict):
            payload = payload.get('sources', [])

        if not isinstance(payload, list):
            return []

        sources: List[Dict[str, Any]] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            if entry.get('enabled', True) is False:
                continue
            base_url = str(entry.get('baseUrl') or '').strip()
            if not base_url:
                continue
            sources.append(entry)

        return sources[: settings.get('onion_max_sources', 8)]

    def _pattern_applies_to_source(self, pattern: Dict[str, Any], source: str) -> bool:
        sources = {
            str(item).upper()
            for item in (pattern.get('sources') or [])
            if str(item).strip()
        }
        if not sources:
            return True

        source_upper = str(source or '').upper()
        alias_map = {
            'ONION_FORUM': {'ONION_FORUM', 'PASTE_SITE', 'THREAT_INTEL_FEED'},
            'PASTE_SITE': {'PASTE_SITE', 'ONION_FORUM'},
            'CREDENTIAL_DUMP': {'CREDENTIAL_DUMP', 'ONION_FORUM'},
            'THREAT_INTEL_FEED': {'THREAT_INTEL_FEED', 'ONION_FORUM'},
        }
        accepted_sources = alias_map.get(source_upper, {source_upper})
        return bool(sources.intersection(accepted_sources))

    # #348 — a free search term (one that fans out a code/repo/paste query) must
    # be discriminating enough that it does not co-occur with random unrelated
    # text. A 1-3-char SLD label / generic acronym (e.g. `qt`, `sol`, `app`)
    # matches an enormous unrelated corpus and is the documented FP source
    # (qt-bonds / questlit / portfolio-app). We require a minimum length for a
    # LOOSE (non-domain) term; a FULL domain (carries a dot) is always specific
    # enough to keep regardless of label length.
    _MIN_LOOSE_TERM_LEN = 4

    def _is_specific_term(self, value: str) -> bool:
        """A term is specific enough to fan a loose search out on when it is a
        full domain (has a dot — e.g. `brand.example`) OR a label of at least
        `_MIN_LOOSE_TERM_LEN` chars. Short, dotless labels are dropped: they are
        the loose-token FP source (#348)."""
        normalized = str(value or '').strip()
        if not normalized:
            return False
        if '.' in normalized:
            return True
        return len(normalized) >= self._MIN_LOOSE_TERM_LEN

    def _extract_search_terms(self, domain: str, patterns: List[Dict[str, Any]]) -> List[str]:
        terms: List[str] = []
        seen = set()

        def add_term(value: str) -> None:
            normalized = str(value or '').strip()
            if not normalized:
                return
            # #348 — drop ultra-short / generic dotless labels: they emit a loose
            # query that co-occurs with unrelated text and float the FP queue.
            if not self._is_specific_term(normalized):
                return
            lowered = normalized.lower()
            if lowered in seen:
                return
            seen.add(lowered)
            terms.append(normalized)

        for pattern in patterns:
            if pattern.get('isRegex'):
                continue
            add_term(pattern.get('pattern', ''))
            add_term(pattern.get('name', ''))
            if len(terms) >= 10:
                break

        add_term(domain.split('.')[0])
        # The full domain is always specific (carries a dot) — guaranteed to pass
        # `_is_specific_term`, so a short-label brand still searchable by domain.
        add_term(domain)

        return terms[:10]

    def _normalize_text(self, content: str) -> str:
        text = re.sub(r'<script\b[^>]*>.*?</script>', ' ', content or '', flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r'<style\b[^>]*>.*?</style>', ' ', text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = unescape(text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _build_onion_urls(self, source: Dict[str, Any], search_terms: List[str], settings: Dict[str, Any]) -> List[str]:
        base_url = str(source.get('baseUrl') or '').rstrip('/')
        urls: List[str] = []

        for static_path in source.get('paths') or []:
            url = urllib.parse.urljoin(base_url + '/', str(static_path).lstrip('/'))
            if url not in urls:
                urls.append(url)

        search_paths = source.get('searchPaths') or []
        for term in search_terms[: settings.get('onion_terms_per_source', 2)]:
            encoded_term = urllib.parse.quote_plus(term)
            for search_path in search_paths:
                rendered_path = str(search_path).replace('{query}', encoded_term).replace('{raw_query}', term)
                url = urllib.parse.urljoin(base_url + '/', rendered_path.lstrip('/'))
                if url not in urls:
                    urls.append(url)

        if not urls:
            urls.append(base_url)

        return urls[: settings.get('onion_max_pages_per_source', 3)]

    async def _fetch_via_tor_http(self, url: str, settings: Dict[str, Any]) -> Optional[Dict[str, str]]:
        proxy_url = settings.get('tor_proxy_url', '').strip()
        if not proxy_url:
            return None

        timeout = settings.get('onion_fetch_timeout_seconds', 45)
        parsed = urllib.parse.urlparse(proxy_url)
        proxy_host = parsed.hostname or proxy_url
        proxy_port = parsed.port or 9050

        command = [
            'curl',
            '--silent',
            '--show-error',
            '--location',
            '--max-time',
            str(timeout),
            '--connect-timeout',
            '20',
            '--socks5-hostname',
            f'{proxy_host}:{proxy_port}',
            '--user-agent',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            url,
        ]

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # #571 — group leader so the watchdog can reap it
        )
        register_group(process)
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(stderr.decode().strip() or f'curl exited with {process.returncode}')

        content = stdout.decode(errors='replace')
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        title = self._normalize_text(title_match.group(1)) if title_match else url
        return {
            'title': title,
            'content': content,
            'fetchMethod': 'curl+socks5',
        }

    async def _fetch_via_tor_browser(self, url: str, settings: Dict[str, Any]) -> Optional[Dict[str, str]]:
        proxy_url = settings.get('tor_proxy_url', '').strip()
        if not proxy_url or async_playwright is None:
            return None

        timeout_ms = settings.get('onion_fetch_timeout_seconds', 45) * 1000
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                proxy={'server': proxy_url},
                args=['--disable-dev-shm-usage'],
            )
            try:
                page = await browser.new_page()
                await page.goto(url, wait_until='domcontentloaded', timeout=timeout_ms)
                await page.wait_for_timeout(1500)
                title = await page.title()
                content = await page.content()
                return {
                    'title': title or url,
                    'content': content,
                    'fetchMethod': 'playwright+tor',
                }
            finally:
                await close_browser_safe(browser)

    def _snippet_around_match(self, text: str, matched_terms: List[str], fallback_length: int = 500) -> str:
        haystack = text or ''
        lowered = haystack.lower()
        for term in matched_terms:
            if not term:
                continue
            idx = lowered.find(term.lower())
            if idx >= 0:
                start = max(0, idx - 180)
                end = min(len(haystack), idx + 320)
                return haystack[start:end].strip()
        return haystack[:fallback_length].strip()

    def _extract_onion_links(self, content: str) -> List[str]:
        if not content:
            return []

        matches = re.findall(
            r'https?://[a-z2-7]{16,56}\.onion[^\s"\'<>)]*',
            content,
            flags=re.IGNORECASE,
        )
        links: List[str] = []
        seen = set()
        for raw in matches:
            normalized = raw.strip()
            if normalized.lower() in seen:
                continue
            seen.add(normalized.lower())
            links.append(normalized)
        return links

    def _filter_external_onion_links(self, links: List[str], source_url: str) -> List[str]:
        source_host = urllib.parse.urlparse(source_url).hostname or ''
        external_links: List[str] = []
        seen = set()

        for link in links:
            host = urllib.parse.urlparse(link).hostname or ''
            normalized = link.strip()
            if not host or host == source_host:
                continue
            lowered = normalized.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            external_links.append(normalized)

        return external_links

    async def _query_onion_forums(self, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        settings = self._get_darkweb_settings(agent)
        if not settings.get('enable_onion_sources'):
            return []

        if not settings.get('tor_proxy_url'):
            if agent:
                agent.report_progress("Onion forum crawling enabled but no Tor proxy is configured")
            return []

        sources = self._load_onion_sources(settings, agent)
        if not sources:
            return []

        if agent:
            agent.report_progress(f"Querying {len(sources)} onion forum source(s) over Tor for {domain}")

        search_terms = self._extract_search_terms(domain, patterns)
        results: List[Dict[str, Any]] = []

        for source in sources:
            source_name = str(source.get('name') or source.get('id') or 'Unknown Onion Source').strip()
            urls = self._build_onion_urls(source, search_terms, settings)

            for url in urls:
                try:
                    if settings.get('onion_use_browser'):
                        fetched = await self._fetch_via_tor_browser(url, settings)
                    else:
                        fetched = await self._fetch_via_tor_http(url, settings)

                    if not fetched:
                        continue

                    normalized_text = self._normalize_text(fetched.get('content', ''))
                    onion_links = self._extract_onion_links(fetched.get('content', ''))
                    external_onion_links = self._filter_external_onion_links(onion_links, source.get('baseUrl', ''))
                    if source.get('requireOnionLinks') and not external_onion_links:
                        continue

                    matched_keywords = self._text_matches_search_terms(
                        f"{fetched.get('title', '')} {normalized_text}",
                        patterns,
                        'ONION_FORUM',
                    )

                    if not matched_keywords:
                        fallback_hay = f"{fetched.get('title', '')} {normalized_text}"
                        matched_keywords = [
                            term for term in search_terms
                            if _plain_term_matches(term, fallback_hay)
                        ][:5]

                    if not matched_keywords:
                        continue

                    severity = str(source.get('severity') or 'HIGH').upper()
                    match_type = str(source.get('matchType') or 'TARGETING_DISCUSSION').upper()
                    result_id = hashlib.sha256(f"{source_name}{url}{domain}".encode()).hexdigest()[:12]
                    snippet = self._snippet_around_match(normalized_text, matched_keywords)

                    stored_source = 'CREDENTIAL_DUMP' if match_type == 'CREDENTIAL_LEAK' else 'PASTE_SITE'

                    results.append({
                        'source': stored_source,
                        'sourceName': source_name,
                        'sourceUrl': url,
                        'sourceId': f"onion-{result_id}",
                        'title': fetched.get('title', source_name),
                        'contentSnippet': snippet or f"Matched {domain} on Tor-accessible source {source_name}",
                        'matchType': match_type,
                        'matchedKeywords': matched_keywords,
                        'severity': severity,
                        'relevanceScore': float(source.get('relevanceScore', 88)),
                        'riskScore': float(source.get('riskScore', 82)),
                        'discoveredAt': None,
                        'metadata': {
                            'network': 'tor',
                            'isOnionSource': True,
                            'sourceCategory': 'ONION_FORUM',
                            'forumId': source.get('id'),
                            'requiresAuth': bool(source.get('requiresAuth', False)),
                            'fetchMethod': fetched.get('fetchMethod'),
                            'linkedOnionUrls': external_onion_links[:10],
                            'sourceKind': source.get('sourceKind'),
                        },
                    })
                except Exception as error:
                    if agent:
                        agent.report_progress(f"Onion source {source_name} failed: {error}")
                await asyncio.sleep(0.5)

        return results

    def _text_matches_search_terms(
        self,
        text: str,
        patterns: List[Dict[str, Any]],
        source_type: str,
    ) -> List[str]:
        haystack = (text or '').lower()
        matched: List[str] = []

        for pattern in patterns:
            if not self._pattern_applies_to_source(pattern, source_type):
                continue

            try:
                is_match = bool(
                    re.search(pattern['pattern'], haystack, re.IGNORECASE)
                    if pattern.get('isRegex')
                    else _plain_term_matches(pattern['pattern'], haystack)
                )
            except re.error:
                is_match = False

            if is_match:
                name = str(pattern.get('name') or pattern.get('pattern') or '').strip()
                if name and name not in matched:
                    matched.append(name)

        return matched

    def _code_gate_patterns(
        self, domain: str, patterns: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """#879 — the token-boundary keep/drop gate terms for the code-platform
        legs. Derived from `_extract_search_terms` — the SAME specificity-filtered
        term list (domain label + full domain + pattern/keyword-derived terms) the
        outbound queries are built from — NOT the raw `patterns` argument, which
        the production dispatch (`DarkWebService.enqueueScanForMonitor`) passes
        EMPTY. Gating on `patterns` alone would drop EVERY code-platform result
        for a monitor with no operator-entered keywords (the common case). The
        specificity filter (`_is_specific_term`, #348) still drops ultra-short
        labels, and matching stays token-boundary via `_text_matches_search_terms`,
        so the qt-bonds / glued-prefix FP class remains dropped."""
        return [
            {'pattern': term, 'name': term, 'isRegex': False}
            for term in self._extract_search_terms(domain, patterns)
        ]

    def _annotate_results_with_patterns(
        self,
        results: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not patterns:
            return results

        annotated = []
        for result in results:
            haystack_parts = [
                str(result.get('title', '')),
                str(result.get('contentSnippet', '')),
                str(result.get('sourceUrl', '')),
                str(result.get('sourceName', '')),
            ]
            metadata = result.get('metadata') or {}
            if metadata:
                try:
                    haystack_parts.append(json.dumps(metadata, default=str))
                except Exception:
                    haystack_parts.append(str(metadata))

            haystack = ' '.join(part for part in haystack_parts if part).lower()
            source = str(result.get('source', '')).upper()
            matched_patterns: List[Dict[str, Any]] = []

            for pattern in patterns:
                if not self._pattern_applies_to_source(pattern, source):
                    continue

                pattern_value = pattern['pattern']
                try:
                    is_match = bool(
                        re.search(pattern_value, haystack, re.IGNORECASE)
                        if pattern.get('isRegex')
                        else _plain_term_matches(pattern_value, haystack)
                    )
                except re.error:
                    is_match = False

                if is_match:
                    matched_patterns.append(pattern)

            existing_keywords = [
                str(keyword) for keyword in (result.get('matchedKeywords') or []) if str(keyword).strip()
            ]
            merged_keywords = existing_keywords + [
                pattern['name']
                for pattern in matched_patterns
                if pattern['name'] not in existing_keywords
            ]
            result['matchedKeywords'] = merged_keywords

            if matched_patterns:
                metadata = dict(result.get('metadata') or {})
                metadata['matchedPatternIds'] = [
                    pattern['id'] for pattern in matched_patterns if pattern.get('id')
                ]
                metadata['matchedPatternNames'] = [
                    pattern['name'] for pattern in matched_patterns
                ]
                result['metadata'] = metadata
                result['relevanceScore'] = min(100, int(result.get('relevanceScore', 0)) + 10)

            annotated.append(result)

        return annotated

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')
        domain = parameters.get('domain', '')
        keywords = parameters.get('keywords', [])
        patterns = parameters.get('patterns', [])
        brand_monitor_id = parameters.get('brandMonitorId', '')
        # #436 — GitHub dork rotation cursor (backend orchestrator threads
        # MonitorEngineState.runCount here). May be absent for manual/legacy
        # callers; _query_github falls back to a stateless wall-clock rotation.
        dork_cohort = parameters.get('dorkCohort')
        # #453 — last-run watermark (backend orchestrator threads the prior
        # MonitorEngineState run timestamp here). Absent → no watermark (legacy
        # full-history behaviour preserved).
        dork_last_run = parameters.get('dorkLastRun')
        # #1474 (P1.5) — on-demand full-cohort sweep. Default OFF; a manual
        # validation / leak-hunt run sets it so ONE invocation exercises every
        # GitHub dork cohort (incl. the budget-deferred overflow) instead of the
        # single rotated cohort a cadence run issues. Bounded by the sweep lease.
        dork_sweep_all = bool(parameters.get('dorkSweepAll', False))
        # #1474 (P2.8) — per-scan budget-deferred dork telemetry, reset here and
        # surfaced on the output so an operator can distinguish a clean result
        # from an unsearched file type.
        self._dork_coverage: List[Dict[str, Any]] = []
        # #889 — owned/defensive domains the credential legs (LeakCheck, HIBP)
        # must sweep in addition to the apex. Backend-supplied, already
        # tenant-scoped + deduped + capped + rotated per cycle; the agent only
        # normalises defensively and sweeps exactly what it receives.
        extra_domains = parameters.get('extraDomains', []) or []
        if isinstance(extra_domains, str):
            extra_domains = json.loads(extra_domains) if extra_domains.startswith('[') else [extra_domains]
        extra_domains = [str(d).strip() for d in extra_domains if str(d or '').strip()]
        settings = self._get_darkweb_settings(agent)
        # 2026-05-16 — SearxNG decommissioned. No longer in the default
        # sources list and the _query_searxng method has been removed from
        # this file. Any caller passing 'searxng' explicitly in `sources` is
        # silently ignored (no-op task fan-out for that key).
        sources = parameters.get('sources', [
            'urlhaus',
            'otx',
            'github',
            'gitlab',
            # 'bitbucket' — removed from the default fan-out: its global repo
            # search endpoint was retired (410 Gone). See _query_bitbucket.
            'npm',
            'gist',
            'stackoverflow',
            'pastebin',
            # #1487 — serper `site:`-dork secret-hunting leg. Reaches the DARK
            # code/paste hosts our native legs miss (Bitbucket, SourceForge,
            # public GitLab, Codeberg, Pastebin) via Google, body-gated. Bounded
            # + leased through the shared SERP_SEARCH quota.
            'serper_dorks',
            'leakcheck',
            'threatfox',
            'ransomware_leaksites',
            # #1611 — Phishing.Database ACTIVE feed (free, keyless, MIT); the
            # first live producer of DarkWebSourceType.PHISHING_DATABASE.
            # #1617 — deliberately NOT in the default set: it is opt-in via an
            # explicit `sources` selection. Unlike every other always-on leg
            # here, it has no per-tenant Integration row to self-disable on
            # (it is keyless), so a default-on producer would arm itself for
            # every tenant and monitor on the next agent deploy with no
            # operator switch. Flood-control doctrine (#764-767) is
            # kill-switch-default-ON; this is the equivalent for a new source.
            'hibp',
            'intelx',
            # #1604 — Hudson Rock Cavalier infostealer-infection posture (free,
            # keyless). Opt-in per tenant via the CAVALIER integration row; with
            # no integration the leg reports `unswept_not_configured`.
            'cavalier',
        ])

        if settings.get('enable_onion_sources') and 'onion_forums' not in sources:
            sources.append('onion_forums')
        max_results = parameters.get('maxResults', 100)

        if isinstance(keywords, str):
            keywords = json.loads(keywords) if keywords.startswith('[') else [keywords]

        normalized_patterns = self._normalize_patterns(keywords, patterns)

        start_time = time.time()
        all_results = []
        sources_queried = 0
        sources_with_hits = 0
        errors = []
        # FEED-2/HONESTY-1 — per-scan feed sweep status (source → swept/unswept/
        # error). Reset each scan; surfaced on the output so ingestion can tell a
        # genuinely-clean leg from one that never answered (401/429/5xx).
        self._source_status = {}

        if agent:
            agent.report_progress(
                current_operation=f"Starting threat intelligence scan for {domain}",
                current_target=domain,
                items_processed=0,
                total_items=len(sources),
            )

        # Query each source
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as session:
            tasks = []

            if 'urlhaus' in sources:
                tasks.append(self._query_urlhaus(session, domain, agent))
            if 'otx' in sources:
                tasks.append(self._query_otx(session, domain, agent))
            if 'github' in sources:
                tasks.append(self._query_github(session, domain, normalized_patterns, agent, dork_cohort, dork_last_run, dork_sweep_all))
            if 'gitlab' in sources:
                tasks.append(self._query_gitlab(session, domain, normalized_patterns, agent))
            if 'bitbucket' in sources:
                tasks.append(self._query_bitbucket(session, domain, normalized_patterns, agent))
            if 'npm' in sources:
                tasks.append(self._query_npm(session, domain, normalized_patterns, agent))
            if 'gist' in sources:
                tasks.append(self._query_gist(session, domain, normalized_patterns, agent))
            if 'serper_dorks' in sources:
                tasks.append(self._query_serper_dorks(session, domain, normalized_patterns, agent))
            if 'stackoverflow' in sources:
                tasks.append(self._query_stackoverflow(session, domain, normalized_patterns, agent))
            if 'pastebin' in sources:
                tasks.append(self._query_pastebin(session, domain, normalized_patterns, agent))
            if 'threatfox' in sources:
                tasks.append(self._query_threatfox(session, domain, agent))
            if 'ransomware_leaksites' in sources:
                tasks.append(self._query_ransomware_leaksites(session, domain, keywords, agent))
            if 'phishing_database' in sources:
                tasks.append(self._query_phishing_database(session, domain, keywords, agent))
            if 'hibp' in sources:
                tasks.append(self._query_hibp_breaches(session, domain, agent, extra_domains))
            if 'intelx' in sources:
                tasks.append(self._query_intelx(session, domain, agent))
            if 'cavalier' in sources:
                # #1619 — ONE task that runs the two Cavalier legs in sequence.
                # They must not be two concurrent gather entries: see
                # _query_cavalier_sequenced for why.
                tasks.append(self._query_cavalier_sequenced(session, domain, agent))
            if 'onion_forums' in sources:
                tasks.append(self._query_onion_forums(domain, normalized_patterns, agent))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                sources_queried += 1
                if isinstance(result, BaseException):
                    # asyncio.gather(return_exceptions=True) widens to
                    # BaseException so Pyright narrows the elif branch.
                    errors.append(str(result))
                elif result:
                    all_results.extend(result)
                    sources_with_hits += 1

            # LeakCheck requires sequential rate-limited calls
            if 'leakcheck' in sources:
                try:
                    lc_results = await self._query_leakcheck(session, domain, agent, extra_domains)
                    if lc_results:
                        all_results.extend(lc_results)
                        sources_with_hits += 1
                    sources_queried += 1
                except Exception as e:
                    errors.append(f"LeakCheck: {str(e)}")
                    sources_queried += 1

        # Always include simulation data if requested or if few results
        use_simulation = (
            'simulation' in sources or
            os.environ.get('DARKWEB_SIMULATION', '').lower() == 'true'
        )

        if use_simulation:
            sim_results = self._load_simulation_data(domain, keywords)
            all_results.extend(sim_results)
            sources_queried += 1
            if sim_results:
                sources_with_hits += 1
            if agent:
                agent.report_progress(
                    current_operation=f"Loaded {len(sim_results)} simulation results",
                    current_target=domain,
                    items_processed=sources_queried,
                    total_items=len(sources),
                )

        # Deduplicate by content hash
        seen_hashes = set()
        unique_results = []
        for r in all_results:
            h = hashlib.sha256(f"{r.get('source','')}{r.get('sourceId','')}{r.get('title','')}".encode()).hexdigest()
            if h not in seen_hashes:
                seen_hashes.add(h)
                unique_results.append(r)

        # Limit results
        unique_results = unique_results[:max_results]
        unique_results = self._annotate_results_with_patterns(unique_results, normalized_patterns)

        # Build severity/matchType breakdowns
        severity_breakdown = {}
        match_type_breakdown = {}
        for r in unique_results:
            sev = r.get('severity', 'MEDIUM')
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            mt = r.get('matchType', 'BRAND_MENTION')
            match_type_breakdown[mt] = match_type_breakdown.get(mt, 0) + 1

        elapsed = time.time() - start_time

        output = {
            'brandMonitorId': brand_monitor_id,
            'domain': domain,
            'keywords': keywords,
            'patterns': normalized_patterns,
            'results': unique_results,
            'summary': {
                'totalMentions': len(unique_results),
                'sourcesQueried': sources_queried,
                'sourcesWithHits': sources_with_hits,
                'severityBreakdown': severity_breakdown,
                'matchTypeBreakdown': match_type_breakdown,
                'errors': errors,
                # FEED-2/HONESTY-1 — per-source sweep status; an UNSWEPT/NEEDKEY/
                # ERROR leg must not read as 'clean'.
                'sourceStatus': dict(self._source_status),
                # #1474 (P2.8) — GitHub dork cohorts whose dorks were
                # budget-deferred this scan; an unsearched file type is NOT a
                # clean result. Empty on a sweep-all run (nothing deferred).
                'dorkCoverage': list(getattr(self, '_dork_coverage', []) or []),
            },
            'tool': 'darkweb',
            'scan_type': 'monitor',
        }

        raw_output = json.dumps(output, indent=2, default=str)

        if agent:
            agent.report_progress(
                current_operation=f"Threat intel scan complete: {len(unique_results)} mentions from {sources_with_hits}/{sources_queried} sources",
                current_target=domain,
                items_processed=sources_queried,
                total_items=sources_queried,
            )
            agent.append_output(raw_output)

        return {
            'success': True,
            'output': output,
            'raw_output': raw_output,
            'execution_metrics': {
                'duration_seconds': round(elapsed, 2),
                'sources_queried': sources_queried,
                'total_results': len(unique_results),
            }
        }

    def _mark_source_status(self, key: str, status: str) -> None:
        """Record a per-scan sweep status for a feed source so a non-200 leg is
        reported as UNSWEPT/NEEDKEY/ERROR (honesty), never silently as 'clean'.

        FEED-2/HONESTY-1: an empty result list from a feed leg is ambiguous —
        'genuinely not listed' vs 'we never got an answer' (401 missing Auth-Key,
        429 rate-limit, 5xx, network error). Distinguishing the two is the whole
        point: a domain listed in URLhaus/ThreatFox must not read healthy because
        the leg silently 401'd. Keys are distinct per source, so concurrent
        gather writes don't race. Surfaced on the tool output as `source_status`.

        `self._source_status` is initialised by execute() at scan start (the
        single reset point); legs are never called outside a scan.
        """
        self._source_status[key] = status

    async def _query_urlhaus(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query abuse.ch URLhaus for domain mentions.

        Sends the mandatory (2024+) `Auth-Key` header from env ABUSECH_KEY. A
        missing key surfaces NEEDKEY (not clean); a non-200 surfaces ERROR.
        """
        results = []
        abusech_key = os.environ.get('ABUSECH_KEY', '').strip()
        if not abusech_key:
            # No key → abuse.ch 401s under the mandatory-Auth-Key regime; the leg
            # is UNSWEPT, not clean. Record and skip the call (no point 401ing).
            self._mark_source_status('urlhaus', 'unswept_needkey')
            return results
        try:
            if agent:
                agent.report_progress(f"Querying URLhaus for {domain}")

            url = 'https://urlhaus-api.abuse.ch/v1/host/'
            async with session.post(url, data={'host': domain}, headers={'Auth-Key': abusech_key}) as resp:
                if resp.status == 401:
                    self._mark_source_status('urlhaus', 'unswept_needkey')
                elif resp.status != 200:
                    self._mark_source_status('urlhaus', f'error_http_{resp.status}')
                else:
                    self._mark_source_status('urlhaus', 'swept')
                    data = await resp.json()
                    urls = data.get('urls', [])
                    for entry in urls[:20]:
                        threat = entry.get('threat', 'malware_download')
                        results.append({
                            'source': 'THREAT_INTEL_FEED',
                            'sourceName': 'URLhaus (abuse.ch)',
                            'sourceUrl': entry.get('url', ''),
                            'sourceId': str(entry.get('id', '')),
                            'title': f"Malicious URL detected: {entry.get('url', domain)}",
                            'contentSnippet': f"URLhaus reports a {threat} threat associated with {domain}. Status: {entry.get('url_status', 'unknown')}. Tags: {', '.join(entry.get('tags', []) or ['none'])}",
                            'matchType': 'MALWARE_C2' if threat == 'malware_download' else 'BRAND_MENTION',
                            'matchedKeywords': [domain],
                            'severity': 'HIGH' if threat == 'malware_download' else 'MEDIUM',
                            'relevanceScore': 85,
                            'riskScore': 80,
                            'discoveredAt': entry.get('date_added', None),
                            'metadata': {
                                'threat': threat,
                                'status': entry.get('url_status'),
                                'tags': entry.get('tags'),
                                'reporter': entry.get('reporter'),
                            }
                        })
        except Exception as e:
            self._mark_source_status('urlhaus', 'error')
            if agent:
                agent.report_progress(f"URLhaus query failed: {str(e)}")
        return results

    async def _query_otx(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query AlienVault OTX for domain intelligence.

        DRP→ASM T2.8c: per-tenant lease via ProviderQuotaService.checkout. If
        the backend has no OTX_API integration configured we fall back to
        anonymous OTX (free tier) — OTX accepts unauthenticated requests with
        reduced rate limits, so a missing integration must not break the
        scan; we just skip the lease and log.

        Feature-flagged via ENABLE_OTX (default off — DRP locked-decision
        #5). When disabled, returns [] immediately without leasing or
        calling OTX.

        FEED-2/HONESTY-1: every exit path records `_mark_source_status('otx', …)`
        so an empty result list is never ambiguous. This leg previously recorded
        NOTHING, so a hard failure (it unpacked `upstream_request`'s (response,
        meta) tuple as a bare response and raised AttributeError into the broad
        `except`) was byte-identical to a genuinely clean sweep. Sibling legs
        (`_query_urlhaus`, `_query_threatfox`, `_query_cavalier`) already follow
        this discipline; OTX was the sole hold-out.
        """
        results: List[Dict] = []

        if not ENABLE_OTX:
            # Off by default. NOT clean — the leg simply did not run.
            self._mark_source_status('otx', 'unswept_disabled')
            if agent:
                agent.report_progress(
                    "OTX query skipped: ENABLE_OTX is off (set ENABLE_OTX=true to enable)"
                )
            return results

        # Try to lease an OTX_API call. If no integration is configured we
        # fall through to anonymous + env-var-key access.
        lease_token: Optional[str] = None
        otx_key = ''
        try:
            lease = await checkout_provider('OTX_API', requested_units=1)
            otx_key = lease.get('apiKey') or ''
            lease_token = lease.get('leaseToken')
        except QuotaExceededError as e:
            self._mark_source_status('otx', 'unswept_quota')
            if agent:
                agent.report_progress(f"OTX quota exceeded: retry in {e.retry_after}s")
            return results
        except IntegrationCredentialsError:
            # No OTX_API integration for this tenant — fall through to the
            # anonymous / env-key free tier. The leg still runs, so no status is
            # recorded here; the call below decides swept vs error.
            otx_key = os.environ.get('OTX_API_KEY', '')

        otx_success = False
        otx_error_code: Optional[str] = None
        resp = None
        try:
            if agent:
                agent.report_progress(f"Querying AlienVault OTX for {domain}")

            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
            headers = {}
            if otx_key:
                headers['X-OTX-API-KEY'] = otx_key

            # Per-call 20s timeout overrides the 120s session total. OTX has a
            # history of intermittent slow responses on rate-limit boundaries;
            # capping the call keeps a stalled OTX from starving the rest of
            # the dark-web scan. Wrap upstream_request (Wave-Quota retry
            # policy) in wait_for to keep the per-call cap intact across
            # backoff attempts.
            #
            # upstream_request returns a (response, meta) TUPLE — unpack it.
            # Binding the tuple to a bare `resp` made every attribute access
            # below raise AttributeError into the broad `except`, which is what
            # took this leg 100% dark while still reporting success.
            resp, _otx_meta = await asyncio.wait_for(
                upstream_request(
                    session, 'GET', url,
                    headers=headers,
                    provider_label='darkweb:otx',
                ),
                timeout=20,
            )
            if resp.status in (401, 403):
                # Bad / rejected key — the leg is UNSWEPT, not clean.
                self._mark_source_status('otx', 'unswept_needkey')
                otx_error_code = f'http_{resp.status}'
            elif resp.status == 429:
                self._mark_source_status('otx', 'unswept_ratelimited')
                otx_error_code = 'http_429'
            elif resp.status != 200:
                self._mark_source_status('otx', f'error_http_{resp.status}')
                otx_error_code = f'http_{resp.status}'
            else:
                self._mark_source_status('otx', 'swept')
                otx_success = True
                data = await resp.json()
                pulses = data.get('pulse_info', {}).get('pulses', [])
                for pulse in pulses[:15]:
                    tags = pulse.get('tags', [])
                    # Determine match type based on tags
                    match_type = 'BRAND_MENTION'
                    severity = 'MEDIUM'
                    if any(t in tags for t in ['phishing', 'credential']):
                        match_type = 'CREDENTIAL_LEAK'
                        severity = 'HIGH'
                    elif any(t in tags for t in ['malware', 'c2', 'botnet', 'trojan']):
                        match_type = 'MALWARE_C2'
                        severity = 'HIGH'
                    elif any(t in tags for t in ['apt', 'targeted']):
                        match_type = 'TARGETING_DISCUSSION'
                        severity = 'HIGH'

                    results.append({
                        'source': 'THREAT_INTEL_FEED',
                        'sourceName': 'AlienVault OTX',
                        'sourceUrl': f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                        'sourceId': pulse.get('id', ''),
                        'title': pulse.get('name', f'OTX Pulse mentioning {domain}'),
                        'contentSnippet': pulse.get('description', '')[:500] or f"Threat intelligence pulse mentioning {domain}. Tags: {', '.join(tags[:10])}",
                        'matchType': match_type,
                        'matchedKeywords': [domain] + [t for t in tags if domain.split('.')[0] in t.lower()][:5],
                        'severity': severity,
                        'relevanceScore': min(95, 50 + len(tags) * 5),
                        'riskScore': min(90, 40 + len(pulses) * 3),
                        'discoveredAt': pulse.get('created', None),
                        'metadata': {
                            'tags': tags[:20],
                            'references': pulse.get('references', [])[:5],
                            'adversary': pulse.get('adversary', None),
                            'targeted_countries': pulse.get('targeted_countries', []),
                        }
                    })
        except asyncio.TimeoutError:
            self._mark_source_status('otx', 'error_timeout')
            otx_success = False
            otx_error_code = 'TimeoutError'
            if agent:
                agent.report_progress("OTX query timed out after 20s")
        except Exception as e:
            self._mark_source_status('otx', 'error')
            otx_success = False
            otx_error_code = type(e).__name__
            if agent:
                agent.report_progress(f"OTX query failed: {str(e)}")
        finally:
            # Free the connection before returning. release() is idempotent
            # on already-closed responses, so this is safe whether the wait_for
            # returned normally, timed out, or raised.
            if resp is not None:
                try:
                    await resp.release()
                except Exception:
                    pass
            if lease_token:
                await reconcile_call(
                    'OTX_API',
                    lease_token,
                    units=1,
                    success=otx_success,
                    error_code=otx_error_code,
                )
        return results

    # GHSECRET-1 — credential-shaped patterns (a value is actually present, not
    # just the WORD 'password'/'secret'). Used to gate a HIGH EXPOSED_SECRET so a
    # repo that merely mentions the brand near a credential keyword does not flood
    # HIGH alerts. Paired with a Shannon-entropy check for opaque tokens.
    _SECRET_PATTERNS = [
        # ── private keys + first-party cloud keys (pre-existing) ──────────────
        re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        re.compile(r'AKIA[0-9A-Z]{16}'),                       # AWS access key id
        re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'),             # GitHub token
        re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}'),           # Slack token
        re.compile(r'AIza[0-9A-Za-z_\-]{35}'),                 # Google API key
        re.compile(r'sk-[A-Za-z0-9]{20,}'),                    # OpenAI-style key
        # ── #1474 vendor-prefixed token families ──────────────────────────────
        # Modelled on the GitLeaks / TruffleHog published detector rule sets and
        # each provider's own token-prefix docs. Prefix-anchored on purpose: a
        # stable vendor prefix is a far lower-FP signal than raw entropy for
        # these shapes, and reaches keys the entropy gate cannot (short, or
        # low-entropy vendor tokens).
        # Stripe secret / restricted / webhook keys — `sk_live_`/`rk_live_`/
        # `sk_test_`/`whsec_` (Stripe API-keys docs; gitleaks `stripe-access-token`).
        re.compile(r'(?:sk|rk)_(?:live|test|prod)_[A-Za-z0-9]{10,}'),
        re.compile(r'whsec_[A-Za-z0-9]{20,}'),
        # Twilio Account SID / API-key SID — `AC`/`SK` + 32 hex (Twilio docs;
        # gitleaks `twilio-api-key`). Prefix-anchored so this is reachable even
        # though a bare 32-hex token cannot satisfy the entropy gate's alphabet.
        re.compile(r'\b(?:AC|SK)[0-9a-fA-F]{32}\b'),
        # SendGrid API key — `SG.<id>.<secret>` (SendGrid docs; gitleaks
        # `sendgrid-api-token`). Segment bounds loosened below the canonical
        # 22/43 so a shorter synthetic still anchors on the stable `SG.` prefix.
        re.compile(r'SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}'),
        # GitLab personal / project access token — `glpat-` + 20 (GitLab docs;
        # gitleaks `gitlab-pat`).
        re.compile(r'glpat-[0-9A-Za-z_\-]{20}'),
        # Google service-account JSON key descriptor (gitleaks `gcp-service-
        # account`). The `"private_key"` body is already caught by the PRIVATE
        # KEY pattern above; this fires on the account descriptor even when the
        # key body is redacted/elided.
        re.compile(r'(?i)"type"\s*:\s*"service_account"'),
        # Azure storage account key inside a connection string (Azure docs;
        # gitleaks `azure-storage-connection-string`).
        re.compile(r'(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{40,}'),
        # Generic JWT — three base64url segments, header begins `eyJ` (gitleaks
        # `jwt`). Reachable independent of entropy (a JWT's `.`-delimited shape
        # is the signal).
        re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}'),
        # Credential embedded in a connection URI — DB drivers plus any scheme
        # carrying an inline `user:pass@` (gitleaks `*-connection-string`).
        # Covers postgres/mysql/mongodb(+srv)/redis/amqp AND a leaked
        # `.git-credentials` `https://user:token@host` line.
        re.compile(
            r'(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|https?)'
            r'://[^\s:@/]+:[^\s@/]{4,}@'
        ),
        # npm registry auth token in `.npmrc` — the `_authToken=` assignment or
        # the `npm_` prefix (gitleaks `npm-access-token`).
        re.compile(r'_authToken\s*=\s*["\']?[A-Za-z0-9_\-./=+]{8,}'),
        re.compile(r'\bnpm_[A-Za-z0-9]{36,}'),
        # ── generic keyword/quoted-assignment (a value is actually present) ────
        # A hardcoded credential is almost always a quoted string literal.
        # Requiring quotes excludes function-call / env-var values
        # (`password = get_password_from_env()`) that the unquoted form FP'd on.
        # #1474: the optional surrounding quotes match a JSON key
        # (`"api_key": "…"`), and the optional identifier prefix/suffix match
        # compound keys (`DJANGO_SECRET_KEY`, `DB_PASSWORD`, `SECRET_KEY = …`) —
        # the two most common real config shapes the anchored form missed. The
        # quoted, space-free, 12+ char value stays the precision guard.
        re.compile(
            r'(?i)["\']?[A-Za-z0-9_]*'
            r'(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)'
            r'[A-Za-z0-9_]*["\']?\s*[:=]\s*[\'"][A-Za-z0-9/+_\-.]{12,}[\'"]'
        ),
    ]

    # #1474 — credential-context words. A bare hex blob (git commit SHA, MD5/
    # SHA digest, hex colour) is indistinguishable from a hex secret by entropy
    # ALONE, so the hex entropy path only fires when one of these appears in the
    # fragment. Non-hex (base64/mixed-alphabet) tokens keep the context-free
    # entropy path — their alphabet richness is itself the discriminator.
    _SECRET_CONTEXT_RE = re.compile(
        r'(?i)(?:api[_-]?key|secret|token|passw|pwd|auth|credential|'
        r'private[_-]?key|access[_-]?key|\bsid\b)'
    )
    _HEX_TOKEN_RE = re.compile(r'^[0-9a-fA-F]+$')

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Shannon entropy (bits/char) — high for random secret-like tokens."""
        if not s:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in s:
            counts[ch] = counts.get(ch, 0) + 1
        n = len(s)
        return -sum((c / n) * log2(c / n) for c in counts.values())

    # Ordered detector labels for `_SECRET_PATTERNS` — the `detectorName` a hit
    # reports (#1477), mirroring the GitLeaks / TruffleHog rule-name convention
    # each regex was modelled on. Index-aligned with `_SECRET_PATTERNS`; a stable
    # unit test (test_darkweb_secret_detection) asserts the two stay the same
    # length so a new pattern without a name fails the build rather than
    # reporting a bare index.
    _SECRET_PATTERN_NAMES = [
        'private-key',
        'aws-access-key-id',
        'github-token',
        'slack-token',
        'google-api-key',
        'openai-api-key',
        'stripe-secret-key',
        'stripe-webhook-secret',
        'twilio-sid',
        'sendgrid-api-key',
        'gitlab-pat',
        'gcp-service-account',
        'azure-storage-key',
        'jwt',
        'connection-string',
        'npmrc-auth-token',
        'npm-access-token',
        'generic-assignment',
    ]

    def _match_secret(self, text: str) -> Optional[Dict[str, Any]]:
        """Return the FIRST secret match detail in `text`, or None (#1477).

        Detail dict: `{ 'value': <matched substring>, 'detectorName': <str> }`.
        `detectorName` is the `_SECRET_PATTERN_NAMES` label for a regex hit, or
        `'high-entropy'` for the charset-aware entropy path. `value` is the exact
        matched span the caller masks + fingerprints — it is NEVER surfaced raw
        (the caller strips it after computing the masked preview + fingerprint).

        Same detection logic + charset-aware entropy gate as the historical
        `_fragment_has_secret` bool (which now delegates here), documented in
        full on that method.
        """
        if not text:
            return None
        for pat, name in zip(self._SECRET_PATTERNS, self._SECRET_PATTERN_NAMES):
            m = pat.search(text)
            if m:
                return {'value': m.group(0), 'detectorName': name}
        has_context = bool(self._SECRET_CONTEXT_RE.search(text))
        for token in re.findall(r'[A-Za-z0-9/+_\-]{20,}', text):
            if self._HEX_TOKEN_RE.match(token):
                if (
                    has_context
                    and len(token) >= 32
                    and self._shannon_entropy(token) >= 3.5
                ):
                    return {'value': token, 'detectorName': 'high-entropy'}
                continue
            if len(set(token)) >= 18 and self._shannon_entropy(token) >= 4.2:
                return {'value': token, 'detectorName': 'high-entropy'}
        return None

    def _fragment_has_secret(self, text: str) -> bool:
        """True when a code fragment carries a credential-shaped token (regex) OR
        a high-entropy opaque token. The bare WORD 'password'/'secret' is NOT
        sufficient (GHSECRET-1).

        Entropy gate (charset-aware — #1474):
        * A base64/mixed-alphabet token (length>=20) must have BOTH entropy>=4.2
          bits/char AND >=18 distinct characters. Long snake_case/SCREAMING_SNAKE
          identifiers top out ~3.98 bits/char (`DEFAULT_REFRESH_TOKEN_EXPIRY_
          SECONDS` = 3.975), whereas a real random base64 token runs ~4.6-4.7
          with 27+ distinct — 4.2 cleanly separates them without losing recall.
        * A HEX-only token can never reach 18 distinct or 4.2 bits/char (the hex
          alphabet caps distinct at 16 and entropy at 4.0), so the base64 rule
          was UNSATISFIABLE for hex — 32/40-hex vendor secrets could never fire
          via entropy. Hex tokens now use hex-scaled thresholds (length>=32,
          entropy>=3.5) BUT only inside a credential context (`_SECRET_CONTEXT_RE`)
          so a bare git commit SHA / digest / hex colour — which carries no
          secret keyword — stays unflagged (no FP flood). Vendor-prefixed hex
          secrets (Twilio `AC…`/`SK…`) are already caught by the regexes above,
          context-free.

        Vendor-specific / low-entropy secrets are caught by the regex patterns
        above; truly opaque unquoted blobs by this check (an unrecognised
        low-entropy token is demoted to a LOW brand mention, still surfaced,
        never a HIGH false positive).

        #1477 — thin bool wrapper over `_match_secret` so the two never diverge;
        existing bool call-sites are unchanged."""
        return self._match_secret(text) is not None

    # ── #1477 — redacted exposed-secret evidence (agent-side masking) ─────────
    # A detected secret is masked HERE, on the agent, so the raw value never
    # leaves the process: only a partially-redacted preview + a non-reversible
    # fingerprint are ever returned. Mirrors how GitHub secret-scanning /
    # GitLeaks / TruffleHog present a finding (short prefix/suffix, mask the
    # middle) and follows OWASP secret-handling (never persist recoverable
    # secret material). The fingerprint is a truncated SHA-256 of the raw value,
    # used for cross-scan / cross-repo DEDUPE only — the same key surfacing in
    # two repos collapses to one fingerprint.
    _SECRET_FINGERPRINT_LEN = 16     # truncated SHA-256 hex chars (dedupe key)
    _SECRET_PREVIEW_PREFIX = 4       # revealed leading chars
    _SECRET_PREVIEW_SUFFIX = 2       # revealed trailing chars
    _SECRET_MIN_PREVIEW_LEN = 12     # below this the value is masked FULLY
    _SECRET_MIN_PREVIEW_ENTROPY = 2.5  # low-entropy → mask fully
    _SECRET_MASK_CHAR = '•'     # '•'

    @classmethod
    def _mask_secret_value(cls, value: str) -> str:
        """Partially-redacted preview of `value` (#1477).

        Reveals the first `_SECRET_PREVIEW_PREFIX` + last `_SECRET_PREVIEW_SUFFIX`
        chars and masks the middle (`AKIA••••••••••••2F`). SHORT-SECRET GUARD:
        a value shorter than `_SECRET_MIN_PREVIEW_LEN`, one where revealing
        prefix+suffix would expose more than ~40% of the token, OR a low-entropy
        token is masked FULLY — never leaking a reconstructable fraction of a
        short/low-entropy secret. Fixed-width mask body (does not echo the true
        length) so the preview leaks neither the secret nor its exact length."""
        v = value or ''
        n = len(v)
        revealed = cls._SECRET_PREVIEW_PREFIX + cls._SECRET_PREVIEW_SUFFIX
        low_entropy = cls._shannon_entropy(v) < cls._SECRET_MIN_PREVIEW_ENTROPY
        # Fully mask: too short, low-entropy, or the revealed fraction would
        # expose >40% of the token (a reconstructable slice).
        if (
            n < cls._SECRET_MIN_PREVIEW_LEN
            or low_entropy
            or revealed > n * 0.4
        ):
            return cls._SECRET_MASK_CHAR * 8
        return (
            v[: cls._SECRET_PREVIEW_PREFIX]
            + cls._SECRET_MASK_CHAR * 8
            + v[-cls._SECRET_PREVIEW_SUFFIX :]
        )

    @classmethod
    def _secret_fingerprint(cls, value: str) -> str:
        """Non-reversible truncated SHA-256 of the RAW secret (#1477).

        DEDUPE-ONLY: stable across scans/repos so the same key collapses to one
        fingerprint; two different secrets differ. Computed here then the raw
        value is discarded — the fingerprint is NOT the value and cannot be
        reversed to it."""
        return hashlib.sha256((value or '').encode('utf-8', 'ignore')).hexdigest()[
            : cls._SECRET_FINGERPRINT_LEN
        ]

    def _build_exposed_secret_evidence(self, match: Dict[str, Any]) -> Dict[str, Any]:
        """Structured, redacted `exposedSecret` evidence object (#1477).

        Input is a `_match_secret` detail dict (`value` + `detectorName`). The
        returned dict carries ONLY masked / non-reversible fields — the raw
        `value` is masked + fingerprinted here and then dropped; an assert
        guards that it never appears verbatim in the output. This object is the
        documented, stable contract an ASM TruffleHog liveness verifier consumes
        (detectorName + secretType + maskedPreview + fingerprint, alongside the
        repo/sha/path the emitter already ships)."""
        raw = match.get('value') or ''
        detector = match.get('detectorName') or 'unknown'
        evidence = {
            'maskedPreview': self._mask_secret_value(raw),
            'detectorName': detector,
            'secretType': detector,
            'length': len(raw),
            'entropyBits': round(self._shannon_entropy(raw), 2),
            'fingerprint': self._secret_fingerprint(raw),
        }
        # Raw-value invariant (defense-in-depth): the full secret string appears
        # in NONE of the returned fields. A short token whose entire body is
        # revealed by an over-generous preview would trip this — the mask guard
        # prevents it, and this assert makes a regression fail loudly.
        if raw:
            for k, val in evidence.items():
                assert raw != val and (not isinstance(val, str) or raw not in val), (
                    f'raw secret leaked into exposedSecret.{k}'
                )
        return evidence

    # ── Cross-provider EXPOSED_SECRET gate ────────────────────────────────────
    # The _fragment_has_secret gate historically ran ONLY in the GitHub path, so
    # GitLab / npm / Stack Overflow / Pastebin / Gist content shipped as a plain
    # LOW BRAND_MENTION — a REAL leaked secret on any non-GitHub provider was
    # silently downgraded. This applies the SAME gate to those providers' fetched
    # content and elevates a hit to the GitHub path's EXACT EXPOSED_SECRET / HIGH
    # shape (matchType + severity, the load-bearing classification). A benign
    # brand mention is left untouched (precision): only a credential-shaped or
    # high-entropy token elevates. Unlike the GitHub path there is no
    # clone-and-verify pass — the content here is the actual fetched artefact
    # (paste/gist body, project/package description), not a repo pointer, so the
    # regex/entropy hit IS the evidence.
    _SECRET_RELEVANCE = 75  # GitHub secret-path relevanceScore
    _SECRET_RISK = 70       # GitHub secret-path riskScore

    def _apply_secret_gate(self, result: Dict[str, Any], content: str) -> Dict[str, Any]:
        """Elevate `result` to a HIGH EXPOSED_SECRET when `content` carries a
        credential-shaped / high-entropy token (same _fragment_has_secret gate as
        GitHub). Otherwise returns it unchanged. Mutates + returns the same dict
        for call-site brevity. Never DEMOTES a provider whose base score already
        clears the GitHub secret floor (max, not overwrite)."""
        if not content or not self._fragment_has_secret(content):
            return result
        result['matchType'] = 'EXPOSED_SECRET'
        result['severity'] = 'HIGH'
        result['relevanceScore'] = max(
            int(result.get('relevanceScore') or 0), self._SECRET_RELEVANCE
        )
        result['riskScore'] = max(
            int(result.get('riskScore') or 0), self._SECRET_RISK
        )
        meta = result.setdefault('metadata', {})
        meta['secretDetected'] = True
        meta['secretGate'] = 'cross-provider'
        orig_title = result.get('title') or result.get('sourceName') or 'source'
        result['title'] = f"Exposed secret in {orig_title}"
        return result

    # ── #436 — rotated GitHub dork cohorts ───────────────────────────────
    # The 28-unit GITHUB_SEARCH lease is already saturated by one cohort's worth
    # of code-searches (4 terms × (1 repo + ≤6 code) ≈ 28), so the full dork set
    # is spread across _GH_NUM_COHORTS scan cycles. The cohort is selected by
    # `dorkCohort = MonitorEngineState.runCount % NUM_COHORTS` (threaded from the
    # backend orchestrator); when the payload omits it a stateless wall-clock
    # rotation keeps manual/legacy runs cycling. repo-search + the `"@<domain>"`
    # email dork run EVERY cycle as the always-on brand-attribution baseline.
    _GH_NUM_COHORTS = 6
    _GH_COHORT_COMMITS = 4
    _GH_COHORT_ISSUES = 5
    # Per-cohort ceiling on code/commit/issue calls (the per-term repo searches
    # are on top; repo(≤4) + cohort(≤24) ≤ 28 lease). _GH_MAX_QUERIES_PER_TERM
    # bounds the per-term code-dork fan-out so 4 terms × 5 + 1 email = 21 ≤ 24.
    _GH_MAX_COHORT_CODE_UNITS = 24
    _GH_MAX_QUERIES_PER_TERM = 6
    # Cohort 0 is the pre-#436 legacy set (6 dorks, NO email prepend) so it stays
    # byte-identical to the old behaviour — preserving the #348 lock and the exact
    # 28-unit budget (4 terms × (1 repo + 6 code) = 28). The email dork is
    # prepended to cohorts 1-5 only (those carry ≤5 code dorks/term, leaving room
    # for it). Lowest-signal ideal-list dorks (filename:credentials/.pgpass/
    # settings.py, extension:cfg/bak) are intentionally deferred for budget —
    # documented here, not silently dropped at runtime. Cohorts 4/5 = commit/issue.
    _GH_LEGACY_COHORT = 0
    # #1474 — high-signal filename/extension dorks. Each cohort's list may run
    # LONGER than _GH_MAX_QUERIES_PER_TERM; the overflow is intentionally
    # budget-DEFERRED at build time (sliced off, telemetry emitted) rather than
    # silently absent. The first _GH_MAX_QUERIES_PER_TERM of each cohort are the
    # searched set; the rest are covered by the on-demand `dorkSweepAll` mode or
    # by rotating cohort membership in a future tuning pass.
    _GH_CODE_DORK_COHORTS = {
        0: [  # legacy keyword + config-file set (the pre-#436 behaviour)
            'password OR secret OR api_key OR token',
            'leak OR credential OR dump',
            'filename:.env', 'extension:yml', 'extension:yaml', 'path:config',
        ],
        1: [  # high-signal credential filenames
            'filename:.npmrc', 'filename:.git-credentials', 'filename:id_rsa',
            'filename:wp-config.php', 'filename:secrets.json',
            'filename:credentials',
            # deferred overflow (#1474):
            'filename:settings.py', 'filename:serviceAccount.json',
            'filename:.dockercfg',
            # filename dorks relocated here from cohort 3 so the brand-specific
            # `api.<domain>` dork survives cohort 3's per-term budget cap (they
            # are filename dorks and belong with the filename cohort).
            'filename:.pgpass', 'filename:.aws/credentials',
            'filename:terraform.tfvars',
            # #1487 net-new high-signal filenames (GitLeaks/TruffleHog rule
            # filenames). Appended after the existing set so they land in the
            # budget-DEFERRED overflow of THIS filename cohort — covered by
            # dorkSweepAll — and never displace an already-searched dork.
            'filename:.netrc', 'filename:.pypirc', 'filename:.htpasswd',
            'filename:database.yml', 'filename:.env.local',
        ],
        2: [  # high-signal credential extensions
            'extension:pem', 'extension:sql', 'extension:json',
            'extension:properties', 'extension:ini', 'extension:key',
            # deferred overflow (#1474):
            'extension:cfg', 'extension:bak', 'extension:pfx', 'extension:p12',
            # #1487 net-new high-signal secret-bearing extensions (VPN profile,
            # Java keystores). Deferred overflow of the extension cohort.
            'extension:ovpn', 'extension:jks', 'extension:keystore',
        ],
        3: [  # brand-specific credential names (api.<domain> appended at build)
            # #1487 — `access_token` added as a 4th credential-name dork. With the
            # build-time `api.<domain>` append that is 5 dorks, still inside the
            # per-term cap of 6, so the appended `api.<domain>` dork is NOT
            # crowded out (the exact #1480 regression this cohort guards against).
            'consumer_key', 'refresh_token', 'client_secret', 'access_token',
        ],
    }

    def _resolve_dork_cohort(self, dork_cohort: Optional[int], domain: str) -> int:
        """Resolve the cohort index for this scan cycle (#436). Prefers the
        backend-threaded runCount cursor; falls back to a STATELESS, deterministic
        wall-clock+domain rotation so a manual/legacy run (no dorkCohort in the
        payload) still cycles cohorts across the 5-container stateless fleet."""
        if isinstance(dork_cohort, int) and dork_cohort >= 0:
            return dork_cohort % self._GH_NUM_COHORTS
        bucket = int(time.time() // 14400)  # 4h buckets == the dark_web cadence
        salt = int(hashlib.sha256((domain or '').encode()).hexdigest(), 16)
        return (bucket + salt) % self._GH_NUM_COHORTS

    # ── #453 — GitHub dork hygiene: watermark + dedup + 1k-cap slicing ───────
    # GitHub Search caps every query at 1,000 results (10 pages × 100). A broad
    # dork silently truncates the remainder; mature monitors WATERMARK each query
    # to the last run, durably DEDUP on (sha|url, secret-fingerprint), and SLICE a
    # >1000 query so each slice stays under the cap (no silent drop).
    _GH_RESULT_CAP = 1000
    # Extension slices for an over-broad CODE query (high-signal leak file types).
    _GH_SLICE_EXTENSIONS = ['env', 'json', 'yml', 'yaml', 'pem', 'sql', 'ini', 'txt']
    _GH_MAX_SLICES = 6

    @staticmethod
    def _github_date_qualifier(endpoint: str, last_run_iso: Optional[str]) -> str:
        """Return the GitHub date qualifier that watermarks `endpoint` to last run.

        Per-endpoint because GitHub uses different qualifiers (and CODE search
        supports NO date qualifier — documented limitation, returns '').
        """
        if not last_run_iso:
            return ''
        date = str(last_run_iso)[:10]  # YYYY-MM-DD
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', date):
            return ''
        return {
            'commits': f'committer-date:>{date}',
            'issues': f'updated:>{date}',
            'repositories': f'pushed:>{date}',
        }.get(endpoint, '')  # 'code' -> '' (no date qualifier on code search)

    @classmethod
    def _apply_watermark(cls, query: str, endpoint: str, last_run_iso: Optional[str]) -> str:
        """Append the watermark qualifier to `query` (no-op when unsupported/absent)."""
        qual = cls._github_date_qualifier(endpoint, last_run_iso)
        return f'{query} {qual}' if qual else query

    @staticmethod
    def _github_result_fingerprint(result: Dict[str, Any]) -> str:
        """Stable cross-run dedup key for a GitHub hit.

        Keyed on (commit SHA | file URL) + a secret fingerprint when a secret was
        detected, so the SAME leak is emitted once even if several cohort queries
        surface it. Mirrored into metadata.dedupeKey so the backend dedups durably.
        """
        meta = result.get('metadata') or {}
        anchor = (meta.get('sha') or result.get('sourceUrl') or result.get('sourceId') or '').strip().lower()
        secret_fp = ''
        if meta.get('secretDetected'):
            snippet = result.get('contentSnippet') or ''
            secret_fp = hashlib.sha1(snippet.encode('utf-8', 'ignore')).hexdigest()[:12]
        return f'{anchor}|{secret_fp}'

    @classmethod
    def _slice_broad_query(cls, query: str, endpoint: str, total_count: int) -> List[str]:
        """Slice a >1000-result query so each slice stays under the GitHub cap.

        CODE queries slice by `extension:` (no date support); commit/issue queries
        slice by yearly `created:` windows. A query at/under the cap is returned
        unchanged. Bounded by _GH_MAX_SLICES.
        """
        if total_count is None or total_count <= cls._GH_RESULT_CAP:
            return [query]
        if endpoint == 'code':
            return [f'{query} extension:{ext}' for ext in cls._GH_SLICE_EXTENSIONS[: cls._GH_MAX_SLICES]]
        # commits / issues: yearly windows back from the current year.
        year = datetime.now().year
        field = 'committer-date' if endpoint == 'commits' else 'created'
        return [
            f'{query} {field}:{y}-01-01..{y}-12-31'
            for y in range(year, year - cls._GH_MAX_SLICES, -1)
        ]

    # #1474 — on-demand full sweep. A manual/validation leak-hunt sets
    # `dorkSweepAll` so ONE run exercises every cohort's dorks (including the
    # budget-deferred overflow), instead of the single rotated cohort a normal
    # cadence run issues. Bounded by _GH_SWEEP_MAX_UNITS so the (larger) sweep
    # lease is never breached; uses fewer terms to keep the fan-out finite.
    _GH_SWEEP_MAX_UNITS = 55
    _GH_MAX_UNITS_SWEEP = 60
    _GH_SWEEP_TERMS = 2

    def _record_deferred_dorks(self, cohort: int, deferred: List[str]) -> None:
        """#1474 (P2.8) — operator-visible skip telemetry for budget-deferred
        dorks. Without this, an unsearched file type is indistinguishable from a
        genuinely clean result. Recorded on `self._dork_coverage` (surfaced on
        the scan output) and logged."""
        if not deferred:
            return
        note = {'cohort': cohort, 'deferredDorks': list(deferred), 'reason': 'per_scan_budget'}
        coverage = getattr(self, '_dork_coverage', None)
        if coverage is None:
            coverage = self._dork_coverage = []
        coverage.append(note)
        logger.info(
            f"[GitHub] cohort {cohort} deferred {len(deferred)} dork(s) for budget "
            f"(run with dorkSweepAll to cover): {', '.join(deferred)}"
        )

    def _build_cohort_queries(
        self, search_terms: List[str], domain: str, cohort: int,
        last_run_iso: Optional[str] = None, sweep: bool = False,
    ) -> List[tuple]:
        """(term, endpoint, query, page) triples for this cycle's cohort (#436).
        endpoint ∈ {'code','commits','issues'}. The `"@<domain>"` email dork is
        prepended to EVERY cohort as the always-on employee-exposure leg (full
        domain → always carries a dot → passes the secret gate's verbatim path
        and the backend brand-relevance gate). The returned list is hard-capped
        at _GH_MAX_COHORT_CODE_UNITS so the lease is never breached.

        #1474 — when `sweep` is set (on-demand full-cohort run) the per-term dork
        slice is lifted so the budget-deferred overflow dorks are included; the
        overall bound is enforced by the caller's _GH_SWEEP_MAX_UNITS cap."""
        max_terms = self._GH_SWEEP_TERMS if sweep else 4
        terms = [t for t in search_terms[:max_terms] if t]
        triples: List[tuple] = []
        c = cohort % self._GH_NUM_COHORTS
        # Always-on employee-exposure leg on every cohort EXCEPT the legacy
        # cohort 0 (which is budget-locked to its 6 code dorks, no email).
        if domain and c != self._GH_LEGACY_COHORT:
            triples.append((domain, 'code', f'"@{domain}"', 1))
        if c == self._GH_COHORT_COMMITS:
            for term in terms:
                triples.append((term, 'commits', f'"{term}"', 1))
            # org/user-scoped commit sweep of the brand's GitHub footprint —
            # personal API tokens leak in commit history (the issue's top miss).
            label = domain.split('.')[0] if domain else ''
            if self._is_specific_term(label):
                for term in terms[:2]:
                    triples.append((term, 'commits', f'"{term}" org:{label}', 1))
        elif c == self._GH_COHORT_ISSUES:
            for term in terms:
                triples.append((term, 'issues', f'"{term}"', 1))
            # deeper paging on the highest-yield config dork (page 2) to reach
            # past items[:5] on high-volume terms.
            for term in terms[:2]:
                triples.append((term, 'code', f'"{term}" filename:.env', 2))
        else:
            suffixes = list(self._GH_CODE_DORK_COHORTS.get(c, []))
            if c == 3 and domain:
                suffixes.append(f'api.{domain}')  # brand API host credential dork
            per_term = len(suffixes) if sweep else self._GH_MAX_QUERIES_PER_TERM
            searched = suffixes[:per_term]
            deferred = suffixes[per_term:]
            if deferred and not sweep:
                self._record_deferred_dorks(c, deferred)
            for term in terms:
                quoted = f'"{term}"'
                for suffix in searched:
                    triples.append((term, 'code', f'{quoted} {suffix}', 1))
        capped = triples[: self._GH_MAX_COHORT_CODE_UNITS]
        # #453 — watermark each query to the last run so we keep slices small and
        # don't re-alert on years-old known leaks every cycle (no-op for code +
        # when last_run_iso is absent → preserves the prior behaviour).
        return [
            (term, endpoint, self._apply_watermark(query, endpoint, last_run_iso), page)
            for (term, endpoint, query, page) in capped
        ]

    def _build_sweep_queries(
        self, search_terms: List[str], domain: str,
        last_run_iso: Optional[str] = None,
    ) -> List[tuple]:
        """#1474 (P1.5) — bounded 'sweep every cohort in one run' query set.
        Iterates all cohorts (including their budget-deferred overflow dorks),
        deduping identical (endpoint, query, page) triples, capped at
        _GH_SWEEP_MAX_UNITS so the sweep lease budget is respected."""
        seen: set = set()
        out: List[tuple] = []
        for c in range(self._GH_NUM_COHORTS):
            for triple in self._build_cohort_queries(
                search_terms, domain, c, last_run_iso, sweep=True
            ):
                term, endpoint, query, page = triple
                key = (endpoint, query, page)
                if key in seen:
                    continue
                seen.add(key)
                out.append(triple)
                if len(out) >= self._GH_SWEEP_MAX_UNITS:
                    return out
        return out

    def _emit_github_match(
        self, *, source_name: str, html_url: str, source_id: str,
        repo_full_name: str, fragment: str, search_term: str, domain: str,
        patterns: List[Dict[str, Any]], path: Optional[str] = None,
        sha: Optional[str] = None, discovered_at: Optional[str] = None,
        leg: str = 'code',
    ) -> Optional[Dict]:
        """Build one CODE_REPOSITORY result from a code/commit/issue hit (#436).
        Shared shape + the GHSECRET-1 gate: a HIGH EXPOSED_SECRET requires a
        credential-shaped/high-entropy token in `fragment`; otherwise a LOW
        BRAND_MENTION. An ABSENT fragment can NEVER mint HIGH (recall-hole guard,
        mirrors the existing fragmentAvailable discriminator). matchedKeywords is
        token-boundary checked (never the raw search term) to avoid the
        flexiti→flexitime / qt-bonds infix-FP class (#348)."""
        fragment_available = bool(fragment and fragment.strip())
        # #1477 — capture the match DETAIL (matched span + detectorName) so a
        # redacted `exposedSecret` evidence object can be built agent-side. The
        # raw span is masked + fingerprinted below and never returned verbatim.
        secret_match = self._match_secret(fragment) if fragment_available else None
        has_secret = secret_match is not None
        exposed_secret = (
            self._build_exposed_secret_evidence(secret_match) if secret_match else None
        )
        # #879 — REAL keep/drop gate. `_text_matches_search_terms` is
        # token-boundary containment (empty on no match); a vendor row with NO
        # genuine match is DROPPED, not kept with the domain stamped as a phantom
        # matched keyword (the old `or [domain]` retention that #348 left behind).
        matched = self._text_matches_search_terms(
            f"{repo_full_name} {fragment}",
            self._code_gate_patterns(domain, patterns),
            'CODE_REPOSITORY',
        )
        if not matched:
            return None
        return {
            'source': 'CODE_REPOSITORY',
            'sourceName': source_name,
            'sourceUrl': html_url,
            'sourceId': source_id,
            'title': (
                f"Exposed secret in {repo_full_name or 'unknown'}"
                if has_secret
                else f"Brand mention in {leg}: {repo_full_name or 'unknown'}"
            ),
            'contentSnippet': (
                f"GitHub {leg} search term '{search_term}' matched in "
                f"{path or repo_full_name or 'unknown'}."
                + (
                    " A credential-shaped/high-entropy token was detected in the matched fragment."
                    if has_secret
                    else " No secret token detected in the matched fragment (brand mention only)."
                )
            ),
            'matchType': 'EXPOSED_SECRET' if has_secret else 'BRAND_MENTION',
            'matchedKeywords': matched,
            'severity': 'HIGH' if has_secret else 'LOW',
            'relevanceScore': 75 if has_secret else 55,
            'riskScore': 70 if has_secret else 40,
            'discoveredAt': discovered_at,
            'metadata': {
                'repository': repo_full_name,
                'path': path,
                'sha': sha,
                'searchTerm': search_term,
                'secretDetected': has_secret,
                'fragmentAvailable': fragment_available,
                'githubLeg': leg,
                # owned-domain reference for the backend relevance gate.
                'domain': domain,
                # #1477 — redacted exposed-secret evidence (masked preview +
                # non-reversible fingerprint + detector). Absent when no secret
                # matched. verificationVerdict is folded in post-verify.
                **({'exposedSecret': exposed_secret} if exposed_secret else {}),
            },
        }

    def _emit_from_github_item(
        self, item: Dict[str, Any], endpoint: str, search_term: str,
        domain: str, patterns: List[Dict[str, Any]],
    ) -> Optional[Dict]:
        """Dispatch one /search/{code,commits,issues} item to _emit_github_match,
        extracting the per-endpoint fragment/url/repo shape (#436). code →
        text_matches; commits → text_matches or commit.message; issues →
        text_matches or title+body. Issues carry no repository object, so the
        repo is derived from html_url (NOT repository_url, which is an API URL)."""
        if not isinstance(item, dict):
            return None
        text_matches = item.get('text_matches') or []
        tm_fragment = ' '.join(m.get('fragment', '') for m in text_matches)
        if endpoint == 'commits':
            repo = item.get('repository') or {}
            commit = item.get('commit') or {}
            fragment = tm_fragment or (commit.get('message') or '')
            return self._emit_github_match(
                source_name=f"GitHub commit - {repo.get('full_name', 'unknown')}",
                html_url=item.get('html_url', ''),
                source_id=f"github-commit-{(item.get('sha') or '')[:12]}",
                repo_full_name=repo.get('full_name', ''),
                fragment=fragment, search_term=search_term, domain=domain,
                patterns=patterns, sha=item.get('sha'),
                discovered_at=(commit.get('author') or {}).get('date'), leg='commit',
            )
        if endpoint == 'issues':
            html_url = item.get('html_url', '')
            parts = html_url.split('/') if html_url else []
            repo_full = '/'.join(parts[3:5]) if len(parts) >= 5 else ''
            fragment = tm_fragment or (
                f"{item.get('title') or ''} {item.get('body') or ''}".strip()
            )
            return self._emit_github_match(
                source_name=f"GitHub issue - {repo_full or 'unknown'}",
                html_url=html_url,
                source_id=f"github-issue-{item.get('id', '')}",
                repo_full_name=repo_full,
                fragment=fragment, search_term=search_term, domain=domain,
                patterns=patterns, discovered_at=item.get('created_at'), leg='issue',
            )
        # default: code search
        repo = item.get('repository') or {}
        return self._emit_github_match(
            source_name=f"GitHub - {repo.get('full_name', 'unknown')}",
            html_url=item.get('html_url', ''),
            source_id=f"github-{(item.get('sha') or '')[:12]}",
            repo_full_name=repo.get('full_name', ''),
            fragment=tm_fragment, search_term=search_term, domain=domain,
            patterns=patterns, path=item.get('path'), sha=item.get('sha'), leg='code',
        )

    # ── #452 — GitHub leak live-verification + commit-history scan ───────────
    # The confidence ladder is pattern < entropy+allowlist < live-verified. A
    # regex/entropy hit is a CANDIDATE; TruffleHog (when available) shallow-clones
    # the repo and scans FULL git history with --only-verified, making a real
    # provider API call to confirm the credential is LIVE — killing the two
    # dominant FP classes (placeholders, already-revoked keys) AND catching
    # secrets removed from HEAD but live in old commit objects.
    _GH_VERIFY_MAX_PER_SCAN = 5      # bound clones per scan (cost + the 180s job cap)
    _GH_CLONE_MAX_MB = 50           # skip oversized repos with an honest status
    _GH_CLONE_DEPTH = 0             # 0 = full history (commit-history reach); see note

    def _derive_clone_url(self, result: Dict[str, Any]) -> str:
        """https clone URL from a github result's repository, or '' if underivable."""
        repo = ((result.get('metadata') or {}).get('repository') or '').strip().strip('/')
        if not repo or '/' not in repo:
            return ''
        return f'https://github.com/{repo}.git'

    def _trufflehog_verdict(self, clone_url: str) -> Dict[str, Any]:
        """Shallow-clone + TruffleHog full-history scan with --only-verified.

        Returns {verdict, detail, historyOnly}. verdict ∈ verified | unverified |
        unsupported-provider | unknown | skipped_oversized | unavailable. NEVER
        raises — any failure degrades to 'unknown' (recall-preserving: we just
        couldn't check).

        #1474 — verdict split. Running WITHOUT `--only-verified` lets us tell
        apart the two "not verified" outcomes TruffleHog otherwise flattens:
        * `unverified` — a detector reached the provider and the provider
          REJECTED the secret (invalid/revoked/placeholder) → safe to demote.
        * `unsupported-provider` — a detector matched but verification could NOT
          complete (no verifier for that provider, or a verification error). A
          real live key of such a provider must NOT be silently demoted, so this
          keeps the candidate severity.
        """
        if not shutil.which('trufflehog'):
            return {'verdict': 'unavailable', 'detail': 'trufflehog not installed'}
        if not shutil.which('git'):
            return {'verdict': 'unavailable', 'detail': 'git not installed'}
        tmp = None
        try:
            tmp = tempfile.mkdtemp(prefix='drp-verify-')
            depth_args = [] if self._GH_CLONE_DEPTH <= 0 else ['--depth', str(self._GH_CLONE_DEPTH)]
            clone = subprocess.run(
                ['git', 'clone', '--quiet', *depth_args, clone_url, tmp],
                capture_output=True, timeout=60, start_new_session=True,  # #571
            )
            if clone.returncode != 0:
                return {'verdict': 'unknown', 'detail': 'clone failed'}
            # size guard — skip oversized repos honestly (no partial verdict).
            size_mb = sum(
                f.stat().st_size for f in Path(tmp).rglob('*') if f.is_file()
            ) / (1024 * 1024)
            if size_mb > self._GH_CLONE_MAX_MB:
                return {'verdict': 'skipped_oversized', 'detail': f'{size_mb:.0f}MB > {self._GH_CLONE_MAX_MB}MB'}
            # #1474 — scan WITHOUT `--only-verified` so unverified findings (and
            # their VerificationError, if any) are visible, letting us split
            # 'unverified' (provider rejected) from 'unsupported-provider'
            # (verification could not run). Each JSON line is one finding.
            th = subprocess.run(
                ['trufflehog', 'git', f'file://{tmp}', '--json', '--no-update'],
                capture_output=True, timeout=120, text=True, start_new_session=True,  # #571
            )
            findings: List[Dict[str, Any]] = []
            for ln in (th.stdout or '').splitlines():
                ln = ln.strip()
                if not ln.startswith('{'):
                    continue
                try:
                    findings.append(json.loads(ln))
                except (ValueError, TypeError):
                    continue
            if not findings:
                return {'verdict': 'unverified', 'detail': 'no secrets detected in history'}
            verified = [f for f in findings if f.get('Verified') is True]
            if verified:
                # historyOnly = the verified finding is not in the working tree HEAD.
                def _commit_not_head(f: Dict[str, Any]) -> bool:
                    git = (((f.get('SourceMetadata') or {}).get('Data') or {}).get('Git') or {})
                    return bool(git.get('commit')) and git.get('commit') != 'HEAD'
                history_only = any(_commit_not_head(f) for f in verified)
                return {'verdict': 'verified', 'detail': f'{len(verified)} verified', 'historyOnly': history_only}
            # Nothing verified. A detector matched but verification did not
            # succeed — split "provider rejected" from "could not verify".
            could_not_verify = any(
                (f.get('VerificationError') or '').strip() for f in findings
            )
            if could_not_verify:
                return {
                    'verdict': 'unsupported-provider',
                    'detail': 'detector matched but verification could not complete',
                }
            return {'verdict': 'unverified', 'detail': 'provider rejected candidate secret(s)'}
        except subprocess.TimeoutExpired:
            return {'verdict': 'unknown', 'detail': 'verify timeout'}
        except Exception as e:  # never sink the scan on a verify failure
            return {'verdict': 'unknown', 'detail': type(e).__name__}
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)

    async def _apply_secret_verification(
        self, results: List[Dict], agent=None, verifier=None,
    ) -> List[Dict]:
        """Promote/demote EXPOSED_SECRET candidates by live-verification verdict.

        verified              → HIGH (confirmed live credential)
        unverified            → demote to LOW (provider rejected the candidate)
        unsupported-provider  → keep severity + honest marker (#1474 — TruffleHog
                                could not verify this provider; a real live key
                                must NOT be silently demoted)
        skipped_oversized     → keep severity + honest marker (couldn't fully check)
        unknown/unavailable   → keep severity + honest marker (recall-preserving)

        `verifier` is an injectable `(clone_url) -> verdict-dict` for tests; in
        production it defaults to the blocking TruffleHog run (off-thread).
        """
        verify = verifier or (lambda url: self._trufflehog_verdict(url))
        budget = self._GH_VERIFY_MAX_PER_SCAN
        for r in results:
            if r.get('matchType') != 'EXPOSED_SECRET':
                continue
            if budget <= 0:
                m = r.setdefault('metadata', {})
                m['verificationVerdict'] = 'unknown'
                m['verificationDetail'] = 'verify budget exhausted'
                if isinstance(m.get('exposedSecret'), dict):
                    m['exposedSecret']['verificationVerdict'] = 'unknown'
                continue
            clone_url = self._derive_clone_url(r)
            if not clone_url:
                m = r.setdefault('metadata', {})
                m['verificationVerdict'] = 'unknown'
                if isinstance(m.get('exposedSecret'), dict):
                    m['exposedSecret']['verificationVerdict'] = 'unknown'
                continue
            budget -= 1
            if agent:
                agent.report_progress(f"Verifying exposed-secret candidate in {clone_url}")
            try:
                verdict = await asyncio.to_thread(verify, clone_url)
            except Exception:
                verdict = {'verdict': 'unknown', 'detail': 'verify error'}
            v = (verdict or {}).get('verdict', 'unknown')
            meta = r.setdefault('metadata', {})
            meta['verificationVerdict'] = v
            meta['verificationDetail'] = (verdict or {}).get('detail')
            # #1477 — fold the verdict into the redacted exposedSecret evidence
            # object too, so the single structured contract the DRP UI / ASM
            # liveness verifier reads carries the live-check outcome alongside
            # the masked preview + fingerprint (still ALSO on metadata for the
            # existing promote/demote branches below).
            if isinstance(meta.get('exposedSecret'), dict):
                meta['exposedSecret']['verificationVerdict'] = v
            if (verdict or {}).get('historyOnly'):
                meta['secretInHistoryOnly'] = True
            if v == 'verified':
                r['matchType'] = 'EXPOSED_SECRET'
                r['severity'] = 'HIGH'
                r['riskScore'] = max(int(r.get('riskScore') or 0), 85)
                r['title'] = f"Verified live secret in {meta.get('repository', 'unknown')}"
            elif v == 'unverified':
                # ran-but-not-live → placeholder/revoked. EXPOSED_SECRET is a
                # HIGH-floored matchType downstream, so a true demotion must drop
                # the matchType to BRAND_MENTION (a repo mention with an
                # unverified-secret marker), not merely lower the severity.
                r['matchType'] = 'BRAND_MENTION'
                r['severity'] = 'LOW'
                r['riskScore'] = min(int(r.get('riskScore') or 50), 40)
                meta['unverifiedSecretCandidate'] = True
                r['title'] = f"Unverified secret candidate (brand mention) in {meta.get('repository', 'unknown')}"
            elif v == 'unsupported-provider':
                # #1474 — TruffleHog matched a candidate but has no working
                # verifier for this provider. Do NOT demote (that would bury a
                # real live leak of an unverifiable provider); keep the candidate
                # EXPOSED_SECRET severity and mark it honestly so an analyst
                # knows it was not live-confirmed.
                meta['unsupportedProvider'] = True
            # unknown / unavailable / skipped_oversized / unsupported-provider →
            # matchType + severity unchanged (recall-preserving), honestly marked.
        return results

    async def _query_github(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None, dork_cohort: Optional[int] = None, dork_last_run: Optional[str] = None, dork_sweep_all: bool = False) -> List[Dict]:
        """Search GitHub repositories and code for brand mentions and exposed secrets.

        DRP→ASM T2.8c: per-tenant lease via ProviderQuotaService.checkout for
        GITHUB_SEARCH. Falls back to GITHUB_TOKEN env var if no integration
        is configured. Reconciles with the actual number of API calls made
        (repo search + code search × terms).

        #350: GITHUB_SEARCH is now a UI-managed DRP integration (DRP Vendors
        tab) — the lease key is the tenant's stored GitHub PAT. The env
        GITHUB_TOKEN remains a one-release fallback for tenants that have not
        configured the integration yet. No change to this checkout/reconcile
        flow is needed.
        """
        results = []

        # Lease GITHUB_SEARCH quota up front. The github_token from the lease
        # supersedes the env var when present.
        lease_token: Optional[str] = None
        github_token = ''
        # #348 — ProviderQuotaService accounting must reflect the REAL GitHub API
        # call count, not a hardcoded 1. Per scan this path issues, over up to 4
        # terms, 1 repo-search + 2 keyword code-searches + up to 4 qualifier
        # code-searches each → at most 4×(1+2+4)=28 calls. Reserve that ceiling at
        # checkout and reconcile the ACTUAL planned count below, so a future
        # GITHUB_SEARCH cap (see #350) fires on real usage rather than 1/28th of
        # it. Initialised before the try so it is always bound in `finally`.
        # #1474 — a full-cohort sweep issues more code searches than a single
        # rotated cohort, so it reserves the larger sweep ceiling. A normal
        # cadence run keeps the 28-unit reservation.
        _GH_MAX_UNITS_PER_SCAN = (
            self._GH_MAX_UNITS_SWEEP if dork_sweep_all else 28
        )
        gh_units = 1
        try:
            lease = await checkout_provider(
                'GITHUB_SEARCH', requested_units=_GH_MAX_UNITS_PER_SCAN
            )
            github_token = lease.get('apiKey') or ''
            lease_token = lease.get('leaseToken')
        except QuotaExceededError as e:
            if agent:
                agent.report_progress(
                    f"GitHub search quota exceeded: retry in {e.retry_after}s"
                )
            return results
        except IntegrationCredentialsError:
            github_token = os.environ.get('GITHUB_TOKEN', '')

        success = True
        error_code: Optional[str] = None
        try:
            if agent:
                agent.report_progress(f"Searching GitHub for {domain}")

            # Use the leased github_token (set above from checkout_provider, with
            # an env fallback only on credential-service failure). The earlier
            # unconditional re-read of GITHUB_TOKEN clobbered the lease key even
            # on a successful 200 lease, bypassing per-tenant quota accounting.
            if not github_token:
                github_token = os.environ.get('GITHUB_TOKEN', '')

            headers = {
                'Accept': 'application/vnd.github.v3+json',
            }
            if github_token:
                headers['Authorization'] = f'token {github_token}'

            search_terms = self._extract_search_terms(domain, patterns)

            for search_term in search_terms[:4]:
                repo_query = f'{search_term} in:name,description,readme'
                # #453 — watermark the repo sweep to the last run (pushed:>DATE).
                repo_query = self._apply_watermark(repo_query, 'repositories', dork_last_run)
                repo_url = f'https://api.github.com/search/repositories?q={urllib.parse.quote(repo_query, safe=":><..in:,@/.")}&sort=updated&order=desc&per_page=8'
                async with session.get(repo_url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get('items', [])
                        for item in items[:5]:
                            repo = item or {}
                            description = repo.get('description') or ''
                            # #879 — REAL keep/drop gate (supersedes #348's label-only
                            # fix): emit ONLY on a genuine token-boundary match. A
                            # vendor row with no match is DROPPED, not kept with the
                            # domain stamped as a phantom matched keyword.
                            matched_keywords = self._text_matches_search_terms(
                                f"{repo.get('full_name', '')} {description}",
                                self._code_gate_patterns(domain, patterns),
                                'CODE_REPOSITORY',
                            )
                            if not matched_keywords:
                                continue
                            results.append({
                                'source': 'CODE_REPOSITORY',
                                'sourceName': 'GitHub',
                                'sourceUrl': repo.get('html_url', ''),
                                'sourceId': f"github-repo-{repo.get('id', '')}",
                                'title': repo.get('full_name', f'GitHub repository matching {search_term}'),
                                'contentSnippet': description or f"Public GitHub repository matching '{search_term}'",
                                'matchType': 'BRAND_MENTION',
                                'matchedKeywords': matched_keywords,
                                'severity': 'LOW',
                                'relevanceScore': 72,
                                'riskScore': 48,
                                'discoveredAt': repo.get('updated_at') or repo.get('created_at'),
                                'metadata': {
                                    'repository': repo.get('full_name'),
                                    'stars': repo.get('stargazers_count', 0),
                                    'language': repo.get('language'),
                                    'searchTerm': search_term,
                                }
                            })
                    elif resp.status == 403 and agent:
                        agent.report_progress("GitHub repository search rate limited")
                        break

                await asyncio.sleep(1)

            if not github_token:
                if agent:
                    agent.report_progress("No GITHUB_TOKEN set, skipping GitHub code search")
                return results

            # #436 — rotated dork cohort. The repo-search above runs every cycle;
            # this cycle's cohort adds the always-on `"@<domain>"` email dork plus
            # the rotated code/commit/issue dorks. The full dork set is covered
            # over _GH_NUM_COHORTS cycles. Keep the GHSECRET-1 entropy gate on
            # every returned fragment (in _emit_github_match).
            # #1474 — sweep mode covers every cohort in one run; cadence mode
            # runs this cycle's single rotated cohort.
            if dork_sweep_all:
                cohort = -1
                cohort_queries = self._build_sweep_queries(search_terms, domain, dork_last_run)
            else:
                cohort = self._resolve_dork_cohort(dork_cohort, domain)
                cohort_queries = self._build_cohort_queries(search_terms, domain, cohort, dork_last_run)
            # #453 — cross-run/within-scan dedup on (sha|url, secret-fingerprint).
            seen_fingerprints: set = set()
            if agent:
                label = 'sweep-all' if dork_sweep_all else f"{cohort}/{self._GH_NUM_COHORTS - 1}"
                agent.report_progress(
                    f"GitHub dork cohort {label}: {len(cohort_queries)} queries"
                )

            # Real GitHub API call count for quota reconciliation: one repo-search
            # per term + one search per cohort query. Bounded by repo(≤4) +
            # cohort(≤_GH_MAX_COHORT_CODE_UNITS) ≤ 28. (Over-counts on an early 403
            # break — fail-SAFE: never under-reports quota usage.)
            gh_units = len(search_terms[:4]) + len(cohort_queries)

            _GH_ENDPOINT_PATH = {
                'code': 'search/code',
                'commits': 'search/commits',
                'issues': 'search/issues',
            }
            # #453 — a >1000-result query silently truncates at the GitHub cap, so
            # the remainder is lost. We process a work-QUEUE: the cohort queries
            # first, and any slice sub-queries we generate when total_count exceeds
            # the cap (bounded by a per-cohort slice budget so the lease holds).
            work_queue: List[tuple] = list(cohort_queries)
            slice_budget = self._GH_MAX_SLICES

            def _emit_items(data_items, endpoint, search_term):
                """Emit deduped results from a search response's items (#453)."""
                for item in (data_items or [])[:5]:
                    emitted = self._emit_from_github_item(
                        item, endpoint, search_term, domain, patterns
                    )
                    if not emitted:
                        continue
                    fp = self._github_result_fingerprint(emitted)
                    if fp in seen_fingerprints:
                        continue  # same (sha|url, secret) already reported this scan
                    seen_fingerprints.add(fp)
                    emitted.setdefault('metadata', {})['dedupeKey'] = fp
                    results.append(emitted)

            qi = 0
            while qi < len(work_queue):
                search_term, endpoint, query, page = work_queue[qi]
                qi += 1
                api_path = _GH_ENDPOINT_PATH.get(endpoint, 'search/code')
                # Encode the query but keep GitHub qualifier punctuation intact.
                encoded = urllib.parse.quote(query, safe=':"@/.<>')
                url = f'https://api.github.com/{api_path}?q={encoded}&per_page=10&page={page}'
                # Request text-match fragments so we entropy-gate the actual
                # matched code/commit/issue rather than minting HIGH on a keyword
                # co-occurrence. Commit search additionally needs the cloak media
                # type to return commit metadata.
                req_headers = {**headers, 'Accept': 'application/vnd.github.v3.text-match+json'}
                if endpoint == 'commits':
                    req_headers['Accept'] = (
                        'application/vnd.github.cloak-preview+json, '
                        'application/vnd.github.v3.text-match+json'
                    )
                try:
                    async with session.get(url, headers=req_headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            total = data.get('total_count', 0) or 0
                            # #453 — over-cap query: slice it (no silent truncation).
                            if total > self._GH_RESULT_CAP and slice_budget > 0:
                                slices = self._slice_broad_query(query, endpoint, total)
                                take = slices[:slice_budget]
                                slice_budget -= len(take)
                                msg = (
                                    f"GitHub query '{query}' total_count={total} > "
                                    f"{self._GH_RESULT_CAP} cap — slicing into {len(take)} "
                                    f"sub-queries to avoid silent truncation"
                                )
                                logger.info(f"[GitHub] {msg}")
                                if agent:
                                    agent.report_progress(msg)
                                for sq in take:
                                    work_queue.append((search_term, endpoint, sq, 1))
                                gh_units += len(take)
                            _emit_items(data.get('items', []), endpoint, search_term)
                        elif resp.status == 422:
                            # malformed qualifier (e.g. a bad `org:`/`user:`) —
                            # skip THIS query, do NOT fall into the 403 break that
                            # aborts the whole leg.
                            continue
                        elif resp.status == 403:
                            if agent:
                                agent.report_progress("GitHub API rate limit reached")
                            break
                except Exception:
                    # one transient query failure must not sink the whole cohort.
                    continue

                await asyncio.sleep(2)  # hold the 10 req/min code-search ceiling

        except Exception as e:
            success = False
            error_code = type(e).__name__
            if agent:
                agent.report_progress(f"GitHub search failed: {str(e)}")
        finally:
            if lease_token:
                await reconcile_call(
                    'GITHUB_SEARCH',
                    lease_token,
                    units=gh_units,  # #348 — real call count, not a hardcoded 1
                    success=success,
                    error_code=error_code,
                )
        # #452/G4a — clone-and-verify pass: a regex/entropy EXPOSED_SECRET is only
        # a CANDIDATE; promote to HIGH only on a live-verified secret, demote a
        # ran-but-not-live verdict, and never lose recall when we simply can't
        # check (no verifier / oversized) — marked honestly either way.
        results = await self._apply_secret_verification(results, agent)
        return results

    async def _query_gitlab(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        """Search GitLab.com for exposed secrets in public code CONTENT (#1487).

        Upgraded from the metadata-only project search (which only ever saw a
        project's name/description) to GitLab's Advanced-Search blob scope —
        `GET /api/v4/search?scope=blobs&search=<term>` searches file CONTENTS +
        filenames, so a credential pasted into a public repo file is now reachable
        and runs through the same cross-provider secret gate as every other leg.

        Token-aware, HONEST degrade (never a silent empty):
          * `scope=blobs` global search on GitLab.com requires authentication AND
            Advanced Search (Elasticsearch). With no token from either source we
            cannot issue it at all → `unswept_needkey` (mirrors the GitHub
            `GITHUB_TOKEN` fallback pattern).
          * A 401/403 (bad/rejected token) → `unswept_needkey`.
          * A scope error (instance lacks Advanced Search → GitLab replies with a
            non-list error body / 400/422) → `degraded`.
          * A 200 blob list → `swept`.
        No compat shim: the metadata query is REPLACED, not aliased.

        #1489: GITLAB_SEARCH is now a UI-managed DRP integration (DRP Vendors
        tab) — the token is resolved via ProviderQuotaService.checkout
        (per-tenant lease), exactly mirroring the GITHUB_SEARCH pattern in
        _query_github. The env GITLAB_TOKEN remains a one-release fallback for
        tenants that have not configured the integration yet. Reconciles with
        the ACTUAL number of blob-search calls made so a GITLAB_SEARCH cap
        fires on real usage."""
        results: List[Dict] = []

        # Lease GITLAB_SEARCH quota up front. The token from the lease
        # supersedes the env var when present. This leg issues at most 4
        # blob-search calls (one per search term); reserve that ceiling at
        # checkout and reconcile the ACTUAL count below.
        _GL_MAX_UNITS_PER_SCAN = 4
        lease_token: Optional[str] = None
        token = ''
        gl_units = 0
        try:
            lease = await checkout_provider(
                'GITLAB_SEARCH', requested_units=_GL_MAX_UNITS_PER_SCAN
            )
            token = (lease.get('apiKey') or '').strip()
            lease_token = lease.get('leaseToken')
        except QuotaExceededError as e:
            # Leased-but-capped: cannot sweep this cycle — report honestly,
            # never a silent false clean.
            self._mark_source_status('gitlab', 'unswept_quota')
            if agent:
                agent.report_progress(
                    f"GitLab search quota exceeded: retry in {e.retry_after}s"
                )
            return results
        except IntegrationCredentialsError:
            # No GITLAB_SEARCH integration configured (or credential service
            # unavailable) — fall back to the env token below.
            token = ''
        if not token:
            token = os.environ.get('GITLAB_TOKEN', '').strip()
        if not token:
            # blob (code-content) search is unauthenticated-unreachable on
            # GitLab.com — report UNSWEPT/NEEDKEY, never a false clean.
            self._mark_source_status('gitlab', 'unswept_needkey')
            if agent:
                agent.report_progress(
                    "GitLab code search skipped: no GITLAB_SEARCH integration "
                    "or GITLAB_TOKEN (scope=blobs requires an authenticated "
                    "Advanced-Search token)"
                )
            if lease_token:
                # Integration existed but carried no usable key and the env
                # fallback is empty — close the lease with zero real calls.
                await reconcile_call(
                    'GITLAB_SEARCH',
                    lease_token,
                    units=0,
                    success=False,
                    error_code='no_token',
                )
            return results
        headers = {'PRIVATE-TOKEN': token}
        gate = self._code_gate_patterns(domain, patterns)
        swept_any = False
        success = True
        error_code: Optional[str] = None
        try:
            if agent:
                agent.report_progress(f"Searching GitLab code for {domain}")

            for search_term in self._extract_search_terms(domain, patterns)[:4]:
                # #1489 — count the REAL blob-search call before issuing it so
                # the reconcile reflects actual usage (mirrors gh_units).
                gl_units += 1
                async with session.get(
                    'https://gitlab.com/api/v4/search',
                    params={
                        'scope': 'blobs',
                        'search': search_term,
                        'per_page': 20,
                    },
                    headers=headers,
                ) as resp:
                    if resp.status in (401, 403):
                        # token missing/rejected — cannot sweep, say so honestly.
                        self._mark_source_status('gitlab', 'unswept_needkey')
                        success = False
                        error_code = f'http_{resp.status}'
                        return results
                    if resp.status != 200:
                        # instance lacks Advanced Search / scope unsupported →
                        # blob search returns 400/422 (or a non-list error body).
                        self._mark_source_status('gitlab', 'degraded')
                        continue
                    blobs = await resp.json()
                    if not isinstance(blobs, list):
                        # scope error surfaced as an object, not a blob list.
                        self._mark_source_status('gitlab', 'degraded')
                        continue
                    swept_any = True
                    for blob in blobs[:10]:
                        if not isinstance(blob, dict):
                            continue
                        # `data` = the matched content lines; `path`/`filename` =
                        # the file. The secret gate runs over the actual content.
                        content = blob.get('data') or ''
                        path = blob.get('path') or blob.get('filename') or ''
                        project_id = blob.get('project_id')
                        # #879 — REAL keep/drop gate on filename + content: a blob
                        # with no brand token-boundary match is dropped.
                        matched = self._text_matches_search_terms(
                            f"{path} {content}", gate, 'CODE_REPOSITORY',
                        )
                        if not matched:
                            continue
                        # Secret detection BEFORE building the row so a hit never
                        # ships the raw secret in contentSnippet (masked preview
                        # only — the raw value never leaves the process, #1477).
                        secret_match = self._match_secret(content)
                        if secret_match:
                            evidence = self._build_exposed_secret_evidence(secret_match)
                            snippet = (
                                f"Exposed secret in GitLab blob {path} "
                                f"(preview {evidence['maskedPreview']})"
                            )
                        else:
                            evidence = None
                            snippet = f"Public GitLab code matching '{search_term}' in {path}"
                        row = {
                            'source': 'CODE_REPOSITORY',
                            'sourceName': 'GitLab',
                            'sourceUrl': (
                                f"https://gitlab.com/search?scope=blobs&search="
                                f"{urllib.parse.quote(search_term)}"
                            ),
                            'sourceId': (
                                f"gitlab-blob-{project_id}-"
                                f"{hashlib.sha1((path + (blob.get('ref') or '')).encode()).hexdigest()[:12]}"
                            ),
                            'title': path or f'GitLab code matching {search_term}',
                            'contentSnippet': snippet,
                            'matchType': 'BRAND_MENTION',
                            'matchedKeywords': matched,
                            'severity': 'LOW',
                            'relevanceScore': 68,
                            'riskScore': 45,
                            'discoveredAt': None,
                            'metadata': {
                                'projectId': project_id,
                                'path': path,
                                'ref': blob.get('ref'),
                                'startline': blob.get('startline'),
                                'searchTerm': search_term,
                            },
                        }
                        # Elevate to EXPOSED_SECRET/HIGH on a credential hit, then
                        # attach the redacted evidence object (raw value dropped).
                        self._apply_secret_gate(row, content)
                        if evidence:
                            row['metadata']['exposedSecret'] = evidence
                        results.append(row)
                await asyncio.sleep(0.5)
            if swept_any:
                self._mark_source_status('gitlab', 'swept')
        except Exception as e:
            success = False
            error_code = type(e).__name__
            self._mark_source_status('gitlab', 'error')
            if agent:
                agent.report_progress(f"GitLab search failed: {str(e)}")
        finally:
            if lease_token:
                await reconcile_call(
                    'GITLAB_SEARCH',
                    lease_token,
                    units=gl_units,  # real call count, not the reserved ceiling
                    success=success,
                    error_code=error_code,
                )
        return results

    async def _query_bitbucket(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        """DISABLED — cleanly, not silently. The prior implementation queried
        `GET /2.0/repositories?q=name~"<term>"` (a global, cross-workspace public
        repository search). Bitbucket retired that endpoint: an unscoped
        `/2.0/repositories` call now returns 410 Gone, and the current API only
        supports repository listing/search SCOPED to a known `{workspace}` — which
        brand monitoring (searching all of Bitbucket for a brand token) has no way
        to enumerate for free. Rather than leave a broken 410 call burning a task
        slot and reporting a false 'swept/clean', the leg is disabled with a
        logged reason and an honest UNSWEPT status so ingestion never reads its
        absence as 'checked, nothing found'. If a workspace-scoped mode is added
        later (operator supplies workspace slugs), re-enable here. `bitbucket` is
        removed from the default source fan-out; an explicit caller reaches this
        no-op."""
        if agent:
            agent.report_progress(
                "Bitbucket source disabled: global repository search endpoint retired "
                "(410 Gone); no free cross-workspace brand search available."
            )
        self._mark_source_status('bitbucket', 'unswept_unsupported')
        return []

    async def _query_npm(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        results = []
        try:
            if agent:
                agent.report_progress(f"Searching npm for {domain}")

            for search_term in self._extract_search_terms(domain, patterns)[:4]:
                async with session.get(
                    'https://registry.npmjs.org/-/v1/search',
                    params={'text': search_term, 'size': 8},
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()
                    for package in data.get('objects', [])[:5]:
                        pkg = package.get('package', {})
                        name = pkg.get('name', '')
                        description = pkg.get('description') or ''
                        # #879 — REAL keep/drop gate: drop a vendor row with no
                        # token-boundary match (no `or [domain]` phantom retention).
                        matched = self._text_matches_search_terms(
                            f"{name} {description}",
                            self._code_gate_patterns(domain, patterns),
                            'CODE_REPOSITORY',
                        )
                        if not matched:
                            continue
                        results.append(self._apply_secret_gate({
                            'source': 'CODE_REPOSITORY',
                            'sourceName': 'npm',
                            'sourceUrl': pkg.get('links', {}).get('npm', ''),
                            'sourceId': f"npm-{name}",
                            'title': name or f'npm package matching {search_term}',
                            'contentSnippet': description or f"Public npm package matching '{search_term}'",
                            'matchType': 'BRAND_MENTION',
                            'matchedKeywords': matched,
                            'severity': 'LOW',
                            'relevanceScore': 60,
                            'riskScore': 38,
                            'discoveredAt': pkg.get('date'),
                            'metadata': {
                                'version': pkg.get('version'),
                                'author': (pkg.get('author') or {}).get('name'),
                                'searchTerm': search_term,
                            }
                        }, description))
                await asyncio.sleep(0.3)
        except Exception as e:
            if agent:
                agent.report_progress(f"npm search failed: {str(e)}")
        return results

    async def _query_gist(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        """GitHub Gists — a top real-world key-leak surface. The public REST API
        has no keyword search, so this sweeps the recent public-gist firehose
        (`GET /gists/public`, free + unauthenticated), brand-matches on the
        description + filenames, and for a matched gist fetches the raw content of
        its small text files and runs the cross-provider secret gate. Bounded:
        one page (100 gists), at most a handful of raw fetches. Free public API →
        no quota lease (same class + pattern as the GitLab/npm/Stack Overflow
        legs; the checkout lease is reserved for paid/registered rate-limited
        vendors). Honest source status so an unswept feed is never read as clean."""
        results = []
        try:
            if agent:
                agent.report_progress(f"Scanning public Gists for {domain}")
            terms = self._extract_search_terms(domain, patterns)
            gate = self._code_gate_patterns(domain, patterns)
            headers = {'Accept': 'application/vnd.github+json'}
            async with session.get(
                'https://api.github.com/gists/public',
                params={'per_page': 100}, headers=headers,
            ) as resp:
                if resp.status != 200:
                    # 403 == unauthenticated 60/hr rate limit exhausted → UNSWEPT,
                    # not clean (HONESTY-1). Mark so ingestion can tell them apart.
                    self._mark_source_status(
                        'gist',
                        'unswept_ratelimited' if resp.status == 403 else f'error_http_{resp.status}',
                    )
                    if agent:
                        agent.report_progress(f"Gist scrape returned status {resp.status}")
                    return results
                self._mark_source_status('gist', 'swept')
                gists = await resp.json()

            raw_fetch_budget = 8  # cap content fetches so one scan stays polite
            for gist in (gists or [])[:100]:
                if not isinstance(gist, dict):
                    continue
                description = gist.get('description') or ''
                files = gist.get('files') or {}
                filenames = ' '.join(files.keys())
                # #879-style keep/drop gate: brand token must appear in the
                # description or a filename (token-boundary), else skip.
                matched = self._text_matches_search_terms(
                    f"{description} {filenames}", gate, 'CODE_REPOSITORY',
                )
                if not matched:
                    continue
                # Fetch the raw content of small text files so the secret gate has
                # the real body (the gist list omits content). Bounded per gist.
                content = ''
                if raw_fetch_budget > 0:
                    for finfo in list(files.values())[:3]:
                        raw_url = (finfo or {}).get('raw_url')
                        size = (finfo or {}).get('size') or 0
                        if not raw_url or size > 200_000:
                            continue
                        raw_fetch_budget -= 1
                        try:
                            async with session.get(raw_url) as rr:
                                if rr.status == 200:
                                    content += (await rr.text())[:8000] + '\n'
                        except Exception:
                            pass
                        if raw_fetch_budget <= 0:
                            break
                owner = (gist.get('owner') or {}).get('login') or 'unknown'
                results.append(self._apply_secret_gate({
                    'source': 'CODE_REPOSITORY',
                    'sourceName': 'Gist',
                    'sourceUrl': gist.get('html_url', ''),
                    'sourceId': f"gist-{gist.get('id', '')}",
                    'title': description or f"Public gist by {owner}",
                    'contentSnippet': (description or content[:300]
                                       or f"Public gist by {owner} ({filenames})"),
                    'matchType': 'BRAND_MENTION',
                    'matchedKeywords': matched,
                    'severity': 'LOW',
                    'relevanceScore': 62,
                    'riskScore': 42,
                    'discoveredAt': gist.get('updated_at') or gist.get('created_at'),
                    'metadata': {
                        'owner': owner,
                        'files': list(files.keys()),
                        'gistId': gist.get('id'),
                    },
                }, f"{description} {content}"))
                await asyncio.sleep(0.1)
        except Exception as e:
            self._mark_source_status('gist', 'error')
            if agent:
                agent.report_progress(f"Gist search failed: {str(e)}")
        return results

    # ── #1487 — serper `site:`-dork secret-hunting leg ────────────────────────
    # Reaches the DARK code/paste hosts our native legs cannot enumerate for free
    # (Bitbucket + SourceForge have no free cross-workspace search; public GitLab
    # and Codeberg + Pastebin are only reachable via a general web search) by
    # dorking Google through the sanctioned Serper.dev reseller interface. On our
    # PAID tier `filetype:` IS supported, so the dorks target secret-bearing file
    # types (`.env`, `.pem`, `.yml`, …) precisely, alongside credential keyword
    # dorks (`client_secret` / `api_key` / …). Bounded + quota-safe: every page is
    # metered through `checkout_provider('SERP_SEARCH')` inside `dispatch_serper`,
    # and a conservative per-scan QUERY budget keeps this leg from starving the
    # sentiment collector that shares the SERP_SEARCH cap.
    _SERPER_DORK_HOSTS = [
        'bitbucket.org', 'sourceforge.net', 'gitlab.com', 'codeberg.org',
        'pastebin.com',
    ]
    # Secret-bearing file types (paid-tier `filetype:` — precise, high-signal).
    _SERPER_DORK_FILETYPES = ['env', 'pem', 'yml', 'json', 'properties']
    # Credential keyword dorks (no filetype — catch inline/embedded secrets).
    _SERPER_DORK_KEYWORDS = [
        'client_secret', 'consumer_key', 'refresh_token', 'api_key', 'credentials',
    ]
    # Conservative fixed per-scan query budget — paid tier means every query
    # costs, and this leg shares the SERP_SEARCH daily cap with the brand-mention
    # sentiment collector, so it gets a small dedicated slice.
    _SERPER_DORK_MAX_QUERIES = 8
    # Body fetches per query (mirror `_query_gist`'s bounded raw fetch).
    _SERPER_DORK_BODY_FETCH_PER_QUERY = 3
    _SERPER_DORK_BODY_MAX_BYTES = 20000

    def _build_serper_dork_queries(self, terms: List[str]) -> List[tuple]:
        """Build the bounded `(host, query)` dork list for this scan (#1487).

        Interleaves `filetype:` dorks (paid-tier, precise) with credential keyword
        dorks and rotates them across the dark hosts, so a small budget still gives
        HOST + OPERATOR diversity. Every query is `site:<host> "<brand>" <op>` — no
        `filetype:` on the free tier caveat no longer applies (paid). Capped at
        `_SERPER_DORK_MAX_QUERIES`; the count deferred is returned so the caller
        can report coverage honestly."""
        brand = (terms[0] if terms else '').strip()
        if not brand:
            return []
        quoted = f'"{brand}"'
        # Interleave filetype + keyword operators for a precise+broad mix.
        operators: List[str] = []
        for i in range(max(len(self._SERPER_DORK_FILETYPES), len(self._SERPER_DORK_KEYWORDS))):
            if i < len(self._SERPER_DORK_FILETYPES):
                operators.append(f'filetype:{self._SERPER_DORK_FILETYPES[i]}')
            if i < len(self._SERPER_DORK_KEYWORDS):
                operators.append(self._SERPER_DORK_KEYWORDS[i])
        queries: List[tuple] = []
        for i, op in enumerate(operators):
            host = self._SERPER_DORK_HOSTS[i % len(self._SERPER_DORK_HOSTS)]
            queries.append((host, f'site:{host} {quoted} {op}'))
        return queries

    async def _fetch_dork_body(self, session: aiohttp.ClientSession, url: str) -> str:
        """Fetch a SERP-hit's page BODY (bounded), or '' on any failure (#1487).

        Split out so the body-gating leg is unit-testable without live HTTP: tests
        stub this to return canned bodies. The BODY — not the 160-char SERP
        snippet — is what the secret gate runs over, because snippet-gating
        over-fires on high-entropy URL fragments (the 5/5 snippet-FP lesson)."""
        try:
            async with session.get(url) as rr:
                if rr.status != 200:
                    return ''
                return (await rr.text())[: self._SERPER_DORK_BODY_MAX_BYTES]
        except Exception:
            return ''

    async def _query_serper_dorks(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        """serper `site:`-dork secret-hunting leg (#1487).

        Issues a small, budgeted set of `site:<host> "<brand>" <filetype/keyword>`
        dorks via `dispatch_serper` (quota-safe, per-page-metered, never exposes
        the key), then for each hit FETCHES THE PAGE BODY and runs the shared
        `_apply_secret_gate` on the BODY. A hit is emitted ONLY when its body
        carries a credential-shaped/high-entropy token — the raw secret is masked
        into a redacted preview here and never stored (a snippet-only high-entropy
        URL fragment whose body has no secret is NOT emitted: the FP guard). Honest
        status: `unswept_no_provider` when SERP is unconfigured (fall-through, no
        job fail), `error_*` on a configured-but-broken provider, `swept` otherwise."""
        results: List[Dict] = []
        terms = [t for t in self._extract_search_terms(domain, patterns) if self._is_specific_term(t)]
        queries = self._build_serper_dork_queries(terms)
        if not queries:
            self._mark_source_status('serper_dorks', 'unswept_no_terms')
            return results
        budgeted = queries[: self._SERPER_DORK_MAX_QUERIES]
        deferred = len(queries) - len(budgeted)
        gate = self._code_gate_patterns(domain, patterns)
        swept_any = False
        seen_fps: set = set()
        if agent:
            agent.report_progress(
                f"SERP secret dorks for {domain}: {len(budgeted)} queries"
                + (f" ({deferred} deferred for budget)" if deferred else "")
            )
        try:
            for host, query in budgeted:
                try:
                    page = await dispatch_serper(query, 1, session)
                except SerpNotConfigured:
                    # Not configured — fall through cleanly (never a false clean).
                    self._mark_source_status('serper_dorks', 'unswept_no_provider')
                    return results
                except SerpSweepFailed as exc:
                    # Configured but broken (401/402/403/429/5xx) — stop, report.
                    self._mark_source_status('serper_dorks', f'error_{exc}')
                    return results
                if page.get('unswept'):
                    # this query blocked (400/5xx) — don't count it clean.
                    continue
                swept_any = True
                hits = page.get('hits') or []
                for hit in hits[: self._SERPER_DORK_BODY_FETCH_PER_QUERY]:
                    url = (hit or {}).get('url')
                    if not url:
                        continue
                    # Body-gate: fetch the actual page, gate the BODY (NOT the
                    # SERP snippet — snippet-gating 5/5-FPs on URL fragments).
                    body = await self._fetch_dork_body(session, url)
                    if not body:
                        continue
                    secret_match = self._match_secret(body)
                    if not secret_match:
                        continue
                    evidence = self._build_exposed_secret_evidence(secret_match)
                    fp = evidence.get('fingerprint')
                    if fp and fp in seen_fps:
                        continue
                    if fp:
                        seen_fps.add(fp)
                    # Brand match on the body for the matched-keyword field (best
                    # effort — the dork already pins the brand, so absence here
                    # does not drop the secret finding).
                    matched = self._text_matches_search_terms(
                        body, gate, 'CODE_REPOSITORY',
                    ) or [terms[0]]
                    row = {
                        'source': 'CODE_REPOSITORY',
                        'sourceName': f'SERP dork ({host})',
                        'sourceUrl': url,
                        'sourceId': f"serper-dork-{hashlib.sha1(url.encode()).hexdigest()[:16]}",
                        'title': (hit or {}).get('title') or f'Public code on {host}',
                        # NO raw body — only a masked preview (raw secret invariant).
                        'contentSnippet': (
                            f"Exposed secret candidate on {host} "
                            f"(preview {evidence['maskedPreview']})"
                        ),
                        'matchType': 'BRAND_MENTION',
                        'matchedKeywords': matched,
                        'severity': 'LOW',
                        'relevanceScore': 62,
                        'riskScore': 42,
                        'discoveredAt': (hit or {}).get('date'),
                        'metadata': {
                            'host': host,
                            'dorkQuery': query,
                            'searchTerm': terms[0],
                            'exposedSecret': evidence,
                        },
                    }
                    # Elevate to EXPOSED_SECRET/HIGH via the shared gate on the BODY.
                    self._apply_secret_gate(row, body)
                    results.append(row)
        except Exception as e:
            self._mark_source_status('serper_dorks', 'error')
            if agent:
                agent.report_progress(f"SERP dork search failed: {str(e)}")
            return results
        self._mark_source_status('serper_dorks', 'swept' if swept_any else 'unswept')
        return results

    async def _query_stackoverflow(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        results = []
        try:
            if agent:
                agent.report_progress(f"Searching Stack Overflow for {domain}")

            for search_term in self._extract_search_terms(domain, patterns)[:4]:
                async with session.get(
                    'https://api.stackexchange.com/2.3/search/advanced',
                    params={
                        'order': 'desc',
                        'sort': 'relevance',
                        'q': search_term,
                        'site': 'stackoverflow',
                        'pagesize': 8,
                        # withbody surfaces the post body so the cross-provider
                        # secret gate can see pasted credentials, not just the
                        # (technology-tag) title. The default filter omits body.
                        'filter': 'withbody',
                    },
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()
                    for item in data.get('items', [])[:5]:
                        title = item.get('title', f'Stack Overflow mention for {search_term}')
                        tags = item.get('tags', [])
                        # #879 — REAL keep/drop gate: drop a vendor row with no
                        # token-boundary match (no `or [domain]` phantom retention).
                        matched = self._text_matches_search_terms(
                            f"{title} {' '.join(tags)}",
                            self._code_gate_patterns(domain, patterns),
                            'CODE_REPOSITORY',
                        )
                        if not matched:
                            continue
                        # #882 — a Stack Overflow Q&A is surface-web PUBLIC CODE, not
                        # threat-actor targeting. Its tags are technology tags
                        # (`python`, `oauth`, …), so default to BRAND_MENTION and only
                        # escalate to TARGETING_DISCUSSION when a REAL threat tag is
                        # present — mirroring the OTX gate at :1143. Stamping every
                        # hit TARGETING_DISCUSSION let surface-web code present with
                        # threat-actor-targeting semantics (and render under "dark
                        # web" downstream).
                        lower_tags = [str(t).lower() for t in tags]
                        so_match_type = (
                            'TARGETING_DISCUSSION'
                            if any(t in lower_tags for t in ['apt', 'targeted'])
                            else 'BRAND_MENTION'
                        )
                        # Secret gate sees the post body (withbody filter) plus the
                        # title; a pasted credential in a Q&A elevates to
                        # EXPOSED_SECRET, a plain tech discussion stays as classified.
                        so_body = str(item.get('body') or '')
                        results.append(self._apply_secret_gate({
                            'source': 'CODE_REPOSITORY',
                            'sourceName': 'Stack Overflow',
                            'sourceUrl': item.get('link', ''),
                            'sourceId': f"stackoverflow-{item.get('question_id', '')}",
                            'title': title,
                            'contentSnippet': f"Public Stack Overflow discussion tagged {', '.join(tags[:5]) or 'general'} matching '{search_term}'",
                            'matchType': so_match_type,
                            'matchedKeywords': matched,
                            'severity': 'LOW',
                            'relevanceScore': 58,
                            'riskScore': 35,
                            'discoveredAt': None,
                            'metadata': {
                                'tags': tags,
                                'score': item.get('score'),
                                'isAnswered': item.get('is_answered'),
                                'searchTerm': search_term,
                            }
                        }, f"{title} {so_body}"))
                await asyncio.sleep(0.3)
        except Exception as e:
            if agent:
                agent.report_progress(f"Stack Overflow search failed: {str(e)}")
        return results

    async def _query_pastebin(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        results = []
        try:
            if agent:
                agent.report_progress(f"Scanning Pastebin scrape feed for {domain}")

            async with session.get('https://scrape.pastebin.com/api_scraping.php', params={'limit': 80}) as resp:
                if resp.status != 200:
                    # PASTEBIN-1 — the Pro-only scraping API returns non-200 when
                    # unsubscribed/rate-limited; an empty list is then UNSWEPT, not
                    # 'clean'. Mark it so ingestion can tell the difference.
                    self._mark_source_status(
                        'pastebin',
                        'unswept_needkey' if resp.status in (401, 403) else f'error_http_{resp.status}',
                    )
                    if agent:
                        agent.report_progress(f"Pastebin scrape returned status {resp.status}")
                    return results
                self._mark_source_status('pastebin', 'swept')
                pastes = await resp.json()

            terms = self._extract_search_terms(domain, patterns)
            semaphore = asyncio.Semaphore(8)

            async def inspect_paste(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
                scrape_url = entry.get('scrape_url')
                full_url = entry.get('full_url') or ''
                if not scrape_url:
                    return None

                async with semaphore:
                    try:
                        async with session.get(scrape_url) as paste_resp:
                            if paste_resp.status != 200:
                                return None
                            content = await paste_resp.text()
                    except Exception:
                        return None

                haystack = f"{entry.get('title', '')}\n{content[:4000]}"
                matched = self._text_matches_search_terms(haystack, patterns, 'PASTE_SITE')
                if not matched:
                    lowered = haystack.lower()
                    matched = [term for term in terms if term.lower() in lowered][:5]
                if not matched:
                    return None

                title = entry.get('title') or f"Paste mentioning {matched[0]}"
                # Pastebin content is the richest secret surface (the full paste
                # body is fetched above) — gate on it so a leaked key in a paste
                # elevates to EXPOSED_SECRET instead of a MEDIUM brand mention.
                return self._apply_secret_gate({
                    'source': 'PASTE_SITE',
                    'sourceName': 'Pastebin',
                    'sourceUrl': full_url,
                    'sourceId': f"pastebin-{entry.get('key', '')}",
                    'title': title,
                    'contentSnippet': content[:500],
                    'matchType': 'BRAND_MENTION',
                    'matchedKeywords': matched,
                    'severity': 'MEDIUM',
                    'relevanceScore': 76,
                    'riskScore': 55,
                    'discoveredAt': entry.get('date'),
                    'metadata': {
                        'syntax': entry.get('syntax'),
                        'size': entry.get('size'),
                        'user': entry.get('user'),
                    }
                }, content)

            inspected = await asyncio.gather(
                *(inspect_paste(entry) for entry in (pastes or [])[:40]),
                return_exceptions=True,
            )
            for item in inspected:
                if isinstance(item, dict):
                    results.append(item)
        except Exception as e:
            self._mark_source_status('pastebin', 'error')
            if agent:
                agent.report_progress(f"Pastebin search failed: {str(e)}")
        return results

    # 2026-05-16 — _query_searxng() removed. SearxNG decommissioned. Stale
    # SearxNG-tagged DarkWebMention rows were purged in the same commit.
    # The native github / gitlab / npm / stackoverflow queries (_query_github
    # etc. above) provide direct coverage of the engines SearxNG was
    # meta-searching across, so no functionality is lost.

    @staticmethod
    def _sanitize_vendor_host(raw: Any) -> Optional[str]:
        """Normalise a host/URL string taken from a VENDOR payload (#1604).

        Hudson Rock's serialization leaks artifacts — a hostname was observed
        live carrying an embedded quote + comma (`login.example.com",`). Never
        trust a vendor host/URL field verbatim: strip quotes/commas/whitespace
        and control characters, cap the length, and require a plausible host
        or http(s) URL shape. Returns None when nothing usable survives, so
        the caller simply omits the field rather than persisting garbage.
        """
        if not isinstance(raw, str):
            return None
        # Drop control chars, then the serialization artifacts (quotes, commas,
        # stray backslashes) and surrounding whitespace.
        cleaned = ''.join(ch for ch in raw if ch.isprintable())
        cleaned = cleaned.strip().strip('",\'\\ \t').strip()
        cleaned = cleaned.replace('"', '').replace("'", '').replace(',', '')
        if not cleaned or len(cleaned) > 512:
            return None
        if cleaned.startswith('http://') or cleaned.startswith('https://'):
            parsed = urllib.parse.urlparse(cleaned)
            if not parsed.netloc or '.' not in parsed.netloc:
                return None
            return cleaned
        # Bare host: must look like a hostname (label.label, no spaces/slashes).
        if re.fullmatch(r'[A-Za-z0-9._\-]+\.[A-Za-z]{2,}', cleaned):
            return cleaned
        return None

    @staticmethod
    def _infostealer_recency_band(last_compromised: Optional[str], kind: str) -> str:
        """Mention-row display band for a Cavalier posture record (#1604).

        NOTE — the backend `classifyInfostealerPosture`
        (backend/src/modules/brand-monitors/alerts/credential-leak-severity.ts)
        is the SSOT for the ALERT severity an analyst acts on; this only bands
        the DarkWebMention row so the mention list is not misleading. Same
        doctrine: recency × side, and raw machine counts NEVER drive the band
        (a big customer-side number is fraud-exposure volume, not a breach of
        the brand's perimeter).
        """
        age_days: Optional[float] = None
        if last_compromised:
            try:
                ts = str(last_compromised).replace('Z', '+00:00')
                parsed = datetime.fromisoformat(ts)
                now = datetime.now(parsed.tzinfo) if parsed.tzinfo else datetime.now()
                age_days = max(0.0, (now - parsed).total_seconds() / 86400.0)
            except Exception:
                age_days = None
        if kind == 'employee':
            if age_days is not None and age_days <= 90:
                return 'HIGH'
            if age_days is not None and age_days <= 365:
                return 'MEDIUM'
            return 'LOW'
        return 'MEDIUM' if (age_days is not None and age_days <= 90) else 'LOW'

    async def _query_cavalier_sequenced(
        self, session: aiohttp.ClientSession, domain: str, agent=None
    ) -> List[Dict]:
        """Run the two Cavalier legs IN ORDER: posture (#1604) then urls (#1612).

        #1619 — both legs make their own upstream call and therefore each take
        their own CAVALIER lease: a scan costs 2 units, not 1. (The #1612
        comment claiming the lease was "reused" was never true — there are two
        `checkout_provider('CAVALIER')` calls.) Two calls costing two units is
        honest accounting and is left as-is.

        What is NOT acceptable is issuing both checkouts CONCURRENTLY from the
        same `asyncio.gather`: on a tenant with one unit left the winner was
        nondeterministic, so the higher-value posture leg — the actual
        infostealer-compromise surface — could lose the race to the urls leg
        and go `unswept_quota` for that cycle. Sequencing makes posture
        deterministically first in line for a scarce unit; the urls leg
        degrades to `unswept_quota` instead, which is the correct precedence.

        Each leg is isolated: a failure in one must not suppress the other
        (they were independent gather entries before, and stay independent in
        effect).
        """
        combined: List[Dict] = []
        try:
            combined.extend(await self._query_cavalier(session, domain, agent))
        except Exception as e:  # noqa: BLE001 — never let one leg kill the other
            logger.error(f"Cavalier posture leg failed: {e}")
        try:
            combined.extend(await self._query_cavalier_urls(session, domain, agent))
        except Exception as e:  # noqa: BLE001
            logger.error(f"Cavalier urls leg failed: {e}")
        return combined

    async def _query_cavalier(
        self, session: aiohttp.ClientSession, domain: str, agent=None
    ) -> List[Dict]:
        """Hudson Rock Cavalier — infostealer-infection POSTURE per domain (#1604).

        FREE, KEYLESS OSINT source: `GET /api/json/v2/osint-tools/
        search-by-domain?domain=<domain>` needs no auth, no API key and no
        account (vendor-confirmed permanently free, with a stated GLOBAL limit
        of 50 requests / 10 seconds shared across all free-tier consumers).

        THE SEMANTIC INVARIANT — the response splits two populations that mean
        completely different things, and conflating them would make the product
        lie to an analyst:
          * `employees` — infections on the brand's OWN STAFF machines that
            captured corporate logins → potential INITIAL ACCESS into the
            customer. The sharp end.
          * `users` (clients) — infections on the brand's CUSTOMERS' own
            machines that captured their logins TO the brand → account-takeover
            / fraud exposure, NOT a breach of the customer's perimeter.
        They are therefore emitted as SEPARATE records (one per side, only when
        that side's count > 0), each carrying a `metadata.infostealer` envelope
        the backend classifier keys on. A combined "N compromised" number is
        never produced anywhere in this leg.

        Quota: the Integration row is REQUIRED even though no key exists — it
        is the per-tenant enable/disable switch and the cap surface (the five
        agent containers do not coordinate in-process). No integration ⇒
        `unswept_not_configured`; capped ⇒ `unswept_quota`. Never a silent
        empty (FEED-2/HONESTY-1).

        Vendor data quality: hostnames/URLs in the payload have been observed
        carrying serialization artifacts (embedded quote + comma), so every
        host/URL is passed through `_sanitize_vendor_host` before it is
        persisted — never trusted verbatim.

        No PII is available or persisted: the free tier returns NO email
        addresses and NO raw passwords (the password blocks are strength
        AGGREGATES only), so no LeakedCredential row is possible from here and
        none is fabricated.
        """
        results: List[Dict] = []

        # Lease CAVALIER quota up front — exactly one upstream call per scan.
        lease_token: Optional[str] = None
        try:
            lease = await checkout_provider('CAVALIER', requested_units=1)
            lease_token = lease.get('leaseToken')
        except QuotaExceededError as e:
            self._mark_source_status('cavalier', 'unswept_quota')
            if agent:
                agent.report_progress(
                    f"Cavalier quota exceeded: retry in {e.retry_after}s"
                )
            return results
        except IntegrationCredentialsError:
            # No CAVALIER integration configured (opt-in per tenant) or the
            # credential service is unavailable — report honestly, never a
            # false clean. The endpoint is keyless but the integration row is
            # the enable switch + cap surface.
            self._mark_source_status('cavalier', 'unswept_not_configured')
            if agent:
                agent.report_progress(
                    "Cavalier skipped: no CAVALIER integration configured for this tenant"
                )
            return results

        target = (domain or '').strip().lower()
        if target.startswith('www.'):
            target = target[4:]

        units = 0
        success = True
        error_code: Optional[str] = None
        try:
            if agent:
                agent.report_progress(f"Querying Hudson Rock Cavalier for {target}")
            units = 1
            async with session.get(
                'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain',
                params={'domain': target},
                timeout=aiohttp.ClientTimeout(total=30, connect=10, sock_read=20),
            ) as resp:
                if resp.status == 429:
                    self._mark_source_status('cavalier', 'unswept_ratelimited')
                    success = False
                    error_code = 'http_429'
                    return results
                if resp.status != 200:
                    self._mark_source_status('cavalier', f'error_http_{resp.status}')
                    success = False
                    error_code = f'http_{resp.status}'
                    return results
                payload = await resp.json(content_type=None)

            if not isinstance(payload, dict):
                self._mark_source_status('cavalier', 'degraded')
                success = False
                error_code = 'non_object_body'
                return results

            self._mark_source_status('cavalier', 'swept')

            def _int(value: Any) -> int:
                try:
                    n = int(value)
                except (TypeError, ValueError):
                    return 0
                return n if n > 0 else 0

            def _iso(value: Any) -> Optional[str]:
                return value.strip() if isinstance(value, str) and value.strip() else None

            # Stealer-family counts (family → count). `total` is a rollup key,
            # not a family; drop it and keep the top few for analyst context.
            families_raw = payload.get('stealerFamilies')
            families: Dict[str, int] = {}
            if isinstance(families_raw, dict):
                pairs = [
                    (str(k), _int(v))
                    for k, v in families_raw.items()
                    if str(k).lower() != 'total' and _int(v) > 0
                ]
                pairs.sort(key=lambda p: p[1], reverse=True)
                families = dict(pairs[:5])

            def _password_stats(block: Any) -> Optional[Dict[str, Any]]:
                """Password STRENGTH aggregates only — no raw passwords exist here."""
                if not isinstance(block, dict):
                    return None
                out: Dict[str, Any] = {}
                total = _int(block.get('totalPass'))
                if total:
                    out['totalPasswords'] = total
                for band in ('too_weak', 'weak', 'medium', 'strong'):
                    entry = block.get(band)
                    if isinstance(entry, dict) and _int(entry.get('qty')):
                        out[band] = _int(entry.get('qty'))
                return out or None

            def _captured_urls(key: str) -> List[Dict[str, Any]]:
                """Top captured login URLs for one side, sanitized (vendor artifacts)."""
                block = payload.get('data')
                raw = block.get(key) if isinstance(block, dict) else None
                out: List[Dict[str, Any]] = []
                if not isinstance(raw, list):
                    return out
                for entry in raw[:5]:
                    if not isinstance(entry, dict):
                        continue
                    url = self._sanitize_vendor_host(entry.get('url'))
                    if not url:
                        continue
                    out.append({'url': url, 'occurrence': _int(entry.get('occurrence'))})
                return out

            sides = [
                {
                    'kind': 'employee',
                    'count': _int(payload.get('employees')),
                    'last': _iso(payload.get('last_employee_compromised')),
                    'passwords': _password_stats(payload.get('employeePasswords')),
                    'urls': _captured_urls('employees_urls'),
                    'fragment': 'employees',
                    'title': (
                        'Infostealer infections on employee machines '
                        f'({_int(payload.get("employees"))}) for {target}'
                    ),
                    'snippet': (
                        f'{_int(payload.get("employees"))} machine(s) belonging to {target} staff '
                        'were infected by infostealer malware that captured corporate logins '
                        '(potential initial access). Employee-side only — customer-side '
                        'infections are reported separately.'
                    ),
                },
                {
                    'kind': 'client',
                    'count': _int(payload.get('users')),
                    'last': _iso(payload.get('last_user_compromised')),
                    'passwords': _password_stats(payload.get('userPasswords')),
                    'urls': _captured_urls('clients_urls'),
                    'fragment': 'clients',
                    'title': (
                        'Infostealer infections on customer devices '
                        f'({_int(payload.get("users"))}) for {target}'
                    ),
                    'snippet': (
                        f'{_int(payload.get("users"))} customer device(s) were infected by '
                        f'infostealer malware that captured their logins to {target} — '
                        'account-takeover / fraud exposure for those customers, NOT a breach '
                        'of the brand perimeter. Reported separately from employee-side '
                        'infections.'
                    ),
                },
            ]

            for side in sides:
                if side['count'] <= 0:
                    continue
                severity = self._infostealer_recency_band(side['last'], side['kind'])
                metadata: Dict[str, Any] = {
                    'vendor': 'HudsonRock:Cavalier',
                    'domain': target,
                    # The envelope the backend classifier keys on. `kind` is the
                    # employee/client discriminator — the whole point.
                    'infostealer': {
                        'kind': side['kind'],
                        'machineCount': side['count'],
                        'lastCompromised': side['last'],
                    },
                    'breachSource': 'Hudson Rock Cavalier',
                }
                if families:
                    metadata['stealerFamilies'] = families
                if side['passwords']:
                    metadata['passwordStrength'] = side['passwords']
                if side['urls']:
                    metadata['capturedLoginUrls'] = side['urls']
                results.append({
                    'source': 'CREDENTIAL_DUMP',
                    'sourceName': 'Hudson Rock Cavalier',
                    # Distinct per-side anchor so the two records dedup
                    # independently across re-scans (the fragment is the
                    # discriminator; the path+query keeps it off the
                    # bare-root dedup path).
                    'sourceUrl': (
                        'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/'
                        f'search-by-domain?domain={urllib.parse.quote(target)}#{side["fragment"]}'
                    ),
                    'sourceId': f'cavalier-{target}-{side["fragment"]}',
                    'title': side['title'],
                    'contentSnippet': side['snippet'],
                    'matchType': 'CREDENTIAL_LEAK',
                    'matchedKeywords': [target],
                    'severity': severity,
                    'relevanceScore': 80,
                    'riskScore': 70 if side['kind'] == 'employee' else 45,
                    'discoveredAt': side['last'],
                    'metadata': metadata,
                })
        except Exception as e:
            success = False
            error_code = type(e).__name__
            self._mark_source_status('cavalier', 'error')
            if agent:
                agent.report_progress(f"Cavalier lookup failed: {str(e)}")
        finally:
            if lease_token:
                await reconcile_call(
                    'CAVALIER',
                    lease_token,
                    units=units,
                    success=success,
                    error_code=error_code,
                )
        return results

    async def _query_cavalier_urls(
        self, session: aiohttp.ClientSession, domain: str, agent=None
    ) -> List[Dict]:
        """Hudson Rock Cavalier `urls-by-domain` — initial-access ROUTE intel (#1612).

        A sibling to `_query_cavalier` (search-by-domain, #1604) that adds the
        PATH-level surface the domain-level posture leg does not: the specific
        login URLs infostealer logs captured for the domain, split into two
        semantically different populations —
          * `employees_urls` — corporate login PORTALS (VPN / webmail / admin)
            staff machines authenticated against → potential INITIAL-ACCESS
            ROUTES into the brand. The higher-signal side.
          * `clients_urls`   — the brand's OWN public login pages that customers'
            infected devices hit → account-takeover / fraud-exposure VOLUME, NOT
            a breach of the brand's perimeter.
        Each side (only when it has URLs) is emitted as a SEPARATE CREDENTIAL_LEAK
        mention carrying a `metadata.infostealer` envelope with the captured
        `initialAccessUrls`. The URL PATH is the value — the host/occurrence
        COUNT never drives severity. The backend keys on the envelope:
        `classifyInitialAccessUrls` bands by SIDE (employee=MEDIUM, client=LOW)
        because `urls-by-domain` carries NO per-URL timestamp (the recency-based
        `classifyInfostealerPosture` path does not apply here).

        Reuses the CAVALIER quota lease exactly like `_query_cavalier` (the
        Integration row is the per-tenant enable/disable + cap surface even
        though the endpoint is keyless). `_mark_source_status('cavalier_urls',
        ...)` on every exit path so a non-200 / malformed body reads as a real
        status, never a silent clean.
        """
        results: List[Dict] = []

        lease_token: Optional[str] = None
        try:
            lease = await checkout_provider('CAVALIER', requested_units=1)
            lease_token = lease.get('leaseToken')
        except QuotaExceededError as e:
            self._mark_source_status('cavalier_urls', 'unswept_quota')
            if agent:
                agent.report_progress(
                    f"Cavalier urls quota exceeded: retry in {e.retry_after}s"
                )
            return results
        except IntegrationCredentialsError:
            self._mark_source_status('cavalier_urls', 'unswept_not_configured')
            if agent:
                agent.report_progress(
                    "Cavalier urls skipped: no CAVALIER integration configured for this tenant"
                )
            return results

        target = (domain or '').strip().lower()
        if target.startswith('www.'):
            target = target[4:]

        units = 0
        success = True
        error_code: Optional[str] = None
        try:
            if agent:
                agent.report_progress(
                    f"Querying Hudson Rock Cavalier initial-access URLs for {target}"
                )
            units = 1
            async with session.get(
                'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain',
                params={'domain': target},
                timeout=aiohttp.ClientTimeout(total=30, connect=10, sock_read=20),
            ) as resp:
                if resp.status == 429:
                    self._mark_source_status('cavalier_urls', 'unswept_ratelimited')
                    success = False
                    error_code = 'http_429'
                    return results
                if resp.status != 200:
                    self._mark_source_status('cavalier_urls', f'error_http_{resp.status}')
                    success = False
                    error_code = f'http_{resp.status}'
                    return results
                payload = await resp.json(content_type=None)

            if not isinstance(payload, dict):
                self._mark_source_status('cavalier_urls', 'degraded')
                success = False
                error_code = 'non_object_body'
                return results

            data = payload.get('data')
            # A 200 with no `data` object is a clean sweep (no captured URLs),
            # not an error — mark swept and return empty.
            self._mark_source_status('cavalier_urls', 'swept')
            if not isinstance(data, dict):
                return results

            def _collect(key: str) -> List[Dict[str, Any]]:
                raw = data.get(key)
                out: List[Dict[str, Any]] = []
                if not isinstance(raw, list):
                    return out
                for entry in raw[:5]:
                    if not isinstance(entry, dict):
                        continue
                    url = self._sanitize_vendor_host(entry.get('url'))
                    if not url:
                        continue
                    occ = entry.get('occurrence')
                    out.append(
                        {
                            'url': url,
                            'occurrence': int(occ) if isinstance(occ, (int, float)) else 0,
                        }
                    )
                return out

            sides = [
                {
                    'kind': 'employee',
                    'urls': _collect('employees_urls'),
                    'fragment': 'employees',
                    'riskScore': 65,
                    # Fallback only; the backend classifyInitialAccessUrls sets
                    # the ALERT severity (employee=MEDIUM). Never drives it.
                    'severity': 'MEDIUM',
                },
                {
                    'kind': 'client',
                    'urls': _collect('clients_urls'),
                    'fragment': 'clients',
                    'riskScore': 40,
                    'severity': 'LOW',
                },
            ]

            for side in sides:
                urls = side['urls']
                if not urls:
                    continue
                if side['kind'] == 'employee':
                    title = (
                        f"Infostealer-captured employee login routes ({len(urls)}) for {target}"
                    )
                    snippet = (
                        f"Infostealer logs captured {len(urls)} corporate login portal(s) "
                        f"(VPN / webmail / admin) for {target} — potential initial-access "
                        f"routes. Employee-side only; customer-side captures are reported "
                        f"separately."
                    )
                else:
                    title = (
                        f"Infostealer-captured customer login routes ({len(urls)}) for {target}"
                    )
                    snippet = (
                        f"Infostealer logs captured {len(urls)} of {target}'s own login page(s) "
                        f"hit by customers' infected devices — account-takeover / fraud exposure "
                        f"for those customers, NOT a breach of the brand perimeter."
                    )
                results.append(
                    {
                        'source': 'CREDENTIAL_DUMP',
                        'sourceName': 'Hudson Rock Cavalier',
                        'sourceUrl': (
                            'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/'
                            f'urls-by-domain?domain={urllib.parse.quote(target)}#{side["fragment"]}'
                        ),
                        'sourceId': f'cavalier-urls-{target}-{side["fragment"]}',
                        'title': title,
                        'contentSnippet': snippet,
                        'matchType': 'CREDENTIAL_LEAK',
                        'matchedKeywords': [target],
                        'severity': side['severity'],
                        'relevanceScore': 75,
                        'riskScore': side['riskScore'],
                        'discoveredAt': None,  # urls-by-domain carries no timestamp
                        'metadata': {
                            'vendor': 'HudsonRock:Cavalier',
                            'domain': target,
                            'breachSource': 'Hudson Rock Cavalier',
                            # The envelope the backend classifier keys on.
                            'infostealer': {
                                'kind': side['kind'],
                                'initialAccessUrls': urls,
                                'lastCompromised': None,
                            },
                            'capturedLoginUrls': urls,
                        },
                    }
                )
        except Exception as e:
            success = False
            error_code = type(e).__name__
            self._mark_source_status('cavalier_urls', 'error')
            if agent:
                agent.report_progress(f"Cavalier urls lookup failed: {str(e)}")
        finally:
            if lease_token:
                await reconcile_call(
                    'CAVALIER',
                    lease_token,
                    units=units,
                    success=success,
                    error_code=error_code,
                )
        return results

    async def _query_leakcheck(
        self,
        session: aiohttp.ClientSession,
        domain: str,
        agent=None,
        extra_domains: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Query LeakCheck public API for credential leaks.

        #889 — sweeps the monitor apex PLUS the tenant's owned/defensive-domain
        cohort (`extra_domains`, backend-supplied: already tenant-scoped,
        deduped, capped, and rotated per scan cycle) so credential coverage is
        not limited to the single apex. Every probe stays under the existing
        ~1 req/s throttle; the backend cap bounds how many domains land in one
        cycle so breadth never bursts into a provider rate-limit.

        The swept cohort is recorded in `sourceStatus.leakcheck`
        (`swept:<d1,d2,...>`), and a rate-limit / per-prefix error records which
        domains + prefixes were left UNSWEPT — never a silent false-clean over
        the un-probed tail.
        """
        results = []
        prefixes = ['info', 'admin', 'support', 'hr', 'sales', 'security', 'noreply', 'contact', 'help', 'billing']

        # Ordered, deduped sweep cohort: apex first, then the owned-domain cohort.
        # Apex-normalise (lowercase, strip a leading `www.`) so a www-prefixed
        # owned domain doesn't duplicate its apex twin.
        sweep_domains: List[str] = []
        seen_domains = set()
        for candidate in [domain] + list(extra_domains or []):
            d = (candidate or '').strip().lower()
            if d.startswith('www.'):
                d = d[4:]
            if d and d not in seen_domains:
                seen_domains.add(d)
                sweep_domains.append(d)

        swept_domains: List[str] = []
        try:
            if agent:
                agent.report_progress(
                    f"Querying LeakCheck for {len(sweep_domains)} domain(s) credential leaks",
                )

            self._mark_source_status('leakcheck', 'swept')
            rate_limited = False
            errored: List[str] = []  # 'target:prefix' probes that raised
            for target in sweep_domains:
                target_errored = False
                for idx, prefix in enumerate(prefixes):
                    email = f"{prefix}@{target}"
                    try:
                        url = f'https://leakcheck.io/api/public?check={email}'
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=15, connect=10, sock_read=10),
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                if data.get('success') and data.get('found', 0) > 0:
                                    sources_list = data.get('sources', [])
                                    for src in sources_list[:5]:
                                        src_name = src.get('name', 'Unknown')
                                        src_date = src.get('date', None)
                                        fields = src.get('fields', [])
                                        has_password = 'password' in [f.lower() for f in fields] if fields else False
                                        results.append({
                                            'source': 'CREDENTIAL_DUMP',
                                            'sourceName': 'LeakCheck (Stealer Logs)',
                                            'sourceUrl': f'https://leakcheck.io/',
                                            'sourceId': f"leakcheck-{email}-{src_name}".replace(' ', '-').lower(),
                                            'title': f"Credential leak found for {email}",
                                            'contentSnippet': f"Found in {src_name}{f' ({src_date})' if src_date else ''}. Exposed fields: {', '.join(fields) if fields else 'unknown'}. Email {email} appears in leaked credential database.",
                                            'matchType': 'CREDENTIAL_LEAK',
                                            'matchedKeywords': [target, email],
                                            'severity': 'CRITICAL' if has_password else 'HIGH',
                                            'relevanceScore': 95 if has_password else 85,
                                            'riskScore': 90 if has_password else 75,
                                            'discoveredAt': src_date,
                                            'metadata': {
                                                'email': email,
                                                'breachSource': src_name,
                                                'breachDate': src_date,
                                                'exposedFields': fields,
                                                'hasPassword': has_password,
                                            }
                                        })
                            elif resp.status == 429:
                                # LEAKCHECK-1 — rate-limited: the remaining prefixes
                                # on THIS domain plus every not-yet-started domain are
                                # UN-QUERIED, so the leg is partially UNSWEPT, not
                                # clean. Record the swept cohort + exactly what was
                                # left pending instead of a silent false-clean.
                                unqueried = prefixes[idx:]
                                pending_domains = sweep_domains[sweep_domains.index(target) + 1:]
                                self._mark_source_status(
                                    'leakcheck',
                                    f'unswept_ratelimited:swept={",".join(swept_domains) or "none"};'
                                    f'pending={target}:{",".join(unqueried)}'
                                    + (f'+{",".join(pending_domains)}' if pending_domains else ''),
                                )
                                if agent:
                                    agent.report_progress(
                                        f"LeakCheck rate limited on {target}, "
                                        f"{len(unqueried)} prefixes + {len(pending_domains)} domain(s) unswept",
                                    )
                                rate_limited = True
                                break
                    except Exception as e:
                        # LEAKCHECK-1 — a transient per-prefix error means this
                        # prefix on this domain was NOT swept; record it and mark
                        # the domain as NOT fully swept (below) so the terminal
                        # status can't false-clean it. The immediate mark is a
                        # fallback for an outer-loop crash before the terminal
                        # compose runs.
                        target_errored = True
                        errored.append(f'{target}:{prefix}')
                        self._mark_source_status('leakcheck', f'partial_error:{target}:{prefix}')
                        if agent:
                            agent.report_progress(f"LeakCheck query for {email} failed: {str(e)}")
                    await asyncio.sleep(1)  # Rate limit: 1 req/sec
                if rate_limited:
                    break
                # Only a domain whose every prefix was answered counts as fully
                # swept — a domain with ANY errored prefix stays out of the
                # 'swept' list so the terminal status reflects it as partial.
                if not target_errored:
                    swept_domains.append(target)

            # Terminal sweep status (skipped when a 429 already recorded
            # 'unswept_ratelimited' and broke out). COV-6/LEAKCHECK-1 honesty: a
            # per-prefix error must NOT be clobbered into a clean 'swept' — if any
            # probe raised, report 'partial_error' with the swept cohort + the
            # exact failed probes; otherwise the fully-swept cohort.
            if not rate_limited:
                if errored:
                    self._mark_source_status(
                        'leakcheck',
                        f'partial_error:swept={",".join(swept_domains) or "none"};'
                        f'errors={",".join(errored)}',
                    )
                elif swept_domains:
                    self._mark_source_status(
                        'leakcheck', f'swept:{",".join(swept_domains)}',
                    )

            if agent and results:
                agent.report_progress(f"LeakCheck found {len(results)} credential leaks")
        except Exception as e:
            if agent:
                agent.report_progress(f"LeakCheck query failed: {str(e)}")
        return results

    async def _query_threatfox(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query ThreatFox (abuse.ch) for IOC data.

        Sends the mandatory (2024+) `Auth-Key` header from env ABUSECH_KEY; a
        missing key surfaces NEEDKEY (not clean), a non-200 surfaces ERROR.
        """
        results = []
        abusech_key = os.environ.get('ABUSECH_KEY', '').strip()
        if not abusech_key:
            self._mark_source_status('threatfox', 'unswept_needkey')
            return results
        try:
            if agent:
                agent.report_progress(f"Querying ThreatFox for {domain}")

            url = 'https://threatfox-api.abuse.ch/api/v1/'
            payload = {"query": "search_ioc", "search_term": domain}
            async with session.post(url, json=payload, headers={'Auth-Key': abusech_key}) as resp:
                if resp.status == 401:
                    self._mark_source_status('threatfox', 'unswept_needkey')
                elif resp.status != 200:
                    self._mark_source_status('threatfox', f'error_http_{resp.status}')
                else:
                    self._mark_source_status('threatfox', 'swept')
                    data = await resp.json()
                    if data.get('query_status') == 'ok':
                        iocs = data.get('data', [])
                        for ioc in (iocs or [])[:15]:
                            ioc_type = ioc.get('ioc_type', '')
                            threat_type = ioc.get('threat_type', '')
                            malware = ioc.get('malware', '')
                            malware_printable = ioc.get('malware_printable', malware)
                            confidence = ioc.get('confidence_level', 50)

                            match_type = 'MALWARE_C2' if threat_type in ['botnet_cc', 'payload_delivery'] else 'BRAND_MENTION'
                            severity = 'CRITICAL' if confidence > 75 else 'HIGH' if confidence > 50 else 'MEDIUM'

                            results.append({
                                'source': 'THREAT_INTEL_FEED',
                                'sourceName': 'ThreatFox (abuse.ch)',
                                'sourceUrl': f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}",
                                'sourceId': f"threatfox-{ioc.get('id', '')}",
                                'title': f"IOC reported: {ioc.get('ioc', domain)} ({malware_printable})",
                                'contentSnippet': f"ThreatFox IOC: {ioc.get('ioc', '')}. Threat type: {threat_type}. Malware: {malware_printable}. Confidence: {confidence}%. Tags: {', '.join(ioc.get('tags', []) or ['none'])}",
                                'matchType': match_type,
                                'matchedKeywords': [domain],
                                'severity': severity,
                                'relevanceScore': min(95, confidence),
                                'riskScore': min(90, confidence),
                                'discoveredAt': ioc.get('first_seen', None),
                                'metadata': {
                                    'iocType': ioc_type,
                                    'threatType': threat_type,
                                    'malware': malware_printable,
                                    'confidence': confidence,
                                    'tags': ioc.get('tags', []),
                                    'reporter': ioc.get('reporter', ''),
                                    'lastSeen': ioc.get('last_seen_utc', None),
                                }
                            })
        except Exception as e:
            self._mark_source_status('threatfox', 'error')
            if agent:
                agent.report_progress(f"ThreatFox query failed: {str(e)}")
        return results

    async def _query_ransomware_leaksites(
        self,
        session: aiohttp.ClientSession,
        domain: str,
        keywords: List[str],
        agent=None,
    ) -> List[Dict]:
        """Query the RansomLook public leak-site tracker for ransomware-gang
        victim claims that name the tenant's brand or owned domain (#888).

        A ransomware gang publishing the org on its leak site is the
        highest-signal dark-web event, so each relevant victim claim is emitted
        as a THREAT_INTEL_FEED mention with matchType RANSOMWARE_VICTIM_CLAIM.
        The emitted severity=HIGH is only the scorer FALLBACK — the backend
        routes RANSOMWARE_VICTIM_CLAIM to the 'leak-claim' bucket and pins it
        HIGH via the ransomwareVictimConfirmed scorer signal (mirrors the #441
        exposed-secret pin), so a plain-mention LOW floor never applies.

        RansomLook's `/api/recent` is a KEYLESS, free public JSON feed (COV-3:
        provisioning paid vendor keys is out of scope) — so, unlike the paid
        vendors (HikerAPI / ScrapeCreators / twitterapi.io), it does NOT lease a
        ProviderQuotaService slot. FEED-2/HONESTY-1: `_mark_source_status(
        'ransomware_leaksites', ...)` is called on EVERY exit path so a non-200
        / malformed-body / network failure reads as ERROR, never a silent
        'clean'.

        Relevance is token-boundary gated (never a bare substring) via
        `_plain_term_matches`, so a short/common brand token landing INSIDE an
        unrelated victim's company name does not fire (false-positive
        containment) — the same discipline the other legs apply.
        """
        results: List[Dict] = []

        # Brand relevance terms: the monitor keywords (brand tokens) + the owned
        # domain (full host) + its registrable core (first label). Deduped,
        # blank-stripped. Token-boundary matching handles the short-token FP risk.
        brand_terms: List[str] = []
        seen_terms = set()
        domain_l = (domain or '').strip().lower()
        for candidate in list(keywords or []) + [domain_l, domain_l.split('.')[0] if domain_l else '']:
            c = (candidate or '').strip().lower()
            if c and c not in seen_terms:
                seen_terms.add(c)
                brand_terms.append(c)

        if not brand_terms:
            # No brand tokens AND no domain configured → nothing to match, and
            # the feed was never contacted. Leave the source UNMARKED (not
            # 'swept') so scan-health does not misreport an un-run leg as clean.
            # In practice `domain` is a required tool param, so this is a
            # misconfiguration guard rather than a normal path.
            return results

        try:
            if agent:
                agent.report_progress(f"Querying RansomLook leak-sites for {domain}")

            url = 'https://www.ransomlook.io/api/recent'
            async with session.get(url, headers={'User-Agent': 'ASM-Platform-DarkWebMonitor'}) as resp:
                if resp.status != 200:
                    self._mark_source_status('ransomware_leaksites', f'error_http_{resp.status}')
                    return results

                data = await resp.json(content_type=None)
                # The feed is a flat array of the most-recent victim posts. A
                # 200 with a non-list body (e.g. a maintenance/error envelope)
                # is a soft failure, not a clean sweep — mark ERROR, don't claim
                # 'swept'. Cap the scan window (cost + relevance falloff).
                if not isinstance(data, list):
                    self._mark_source_status('ransomware_leaksites', 'error')
                    return results

                self._mark_source_status('ransomware_leaksites', 'swept')
                for post in data[:200]:
                    if not isinstance(post, dict):
                        continue
                    victim = str(post.get('post_title', '') or '').strip()
                    group = str(post.get('group_name', '') or '').strip()
                    description = str(post.get('description', '') or '').strip()
                    link = str(post.get('link', '') or '')
                    discovered = post.get('discovered')

                    # Token-boundary relevance gate over the observable post text.
                    haystack = ' '.join([victim, description, link])
                    matched = [t for t in brand_terms if _plain_term_matches(t, haystack)]
                    if not matched:
                        continue

                    group_label = group or 'unknown group'
                    sid = hashlib.sha1(
                        f"{group}|{victim}|{link}".encode('utf-8', 'ignore')
                    ).hexdigest()[:12]

                    results.append({
                        'source': 'THREAT_INTEL_FEED',
                        'sourceName': f"RansomLook ({group_label})",
                        'sourceUrl': link or 'https://www.ransomlook.io/recent',
                        'sourceId': f"ransomlook-{sid}",
                        'title': f"Ransomware victim claim: {victim} ({group_label})",
                        'contentSnippet': (
                            f"{group_label} listed \"{victim}\" as a victim on its ransomware "
                            f"leak site. {description}"
                        )[:500],
                        'matchType': 'RANSOMWARE_VICTIM_CLAIM',
                        'matchedKeywords': matched,
                        # Fallback severity only; the scorer pins HIGH via
                        # ransomwareVictimConfirmed (see the backend listener/scorer).
                        'severity': 'HIGH',
                        'relevanceScore': 95,
                        'riskScore': 90,
                        'discoveredAt': discovered,
                        'metadata': {
                            'ransomwareGroup': group,
                            'victimName': victim,
                            'leakSiteUrl': link,
                            'discovered': discovered,
                            'feed': 'ransomlook.io',
                        },
                    })
        except Exception as e:
            self._mark_source_status('ransomware_leaksites', 'error')
            if agent:
                agent.report_progress(f"RansomLook query failed: {str(e)}")
        return results

    async def _fetch_phishing_domains(
        self, session: aiohttp.ClientSession, agent=None
    ) -> Optional[set]:
        """Fetch + cache the Phishing.Database ACTIVE-domains feed (#1611).

        Returns the set of active phishing domains (lowercased), or None on a
        hard fetch failure (the caller marks the source ERROR — never a silent
        clean). Process-wide TTL cache + conditional GET (If-None-Match) so a
        304 refreshes the TTL without re-downloading ~11 MB. Guarded by a lock
        so concurrent scans in one process do not stampede the CDN.
        """
        now = time.time()
        cache = _phishing_db_cache
        # Fast path: fresh cache, no lock/HTTP needed.
        if (
            cache["domains"] is not None
            and (now - cache["fetched_at"]) < _PHISHING_DB_TTL_SECONDS
        ):
            return cache["domains"]

        async with _get_phishing_db_lock():
            # Re-check under the lock — another coroutine may have refreshed it.
            now = time.time()
            if (
                cache["domains"] is not None
                and (now - cache["fetched_at"]) < _PHISHING_DB_TTL_SECONDS
            ):
                return cache["domains"]

            headers = {"User-Agent": "ASM-Platform-DarkWebMonitor"}
            if cache["etag"]:
                headers["If-None-Match"] = cache["etag"]
            async with session.get(
                _PHISHING_DB_URL,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60, connect=15, sock_read=45),
            ) as resp:
                if resp.status == 304 and cache["domains"] is not None:
                    # Not modified — keep the cached set, refresh the TTL.
                    cache["fetched_at"] = now
                    return cache["domains"]
                if resp.status != 200:
                    # Hard failure with no usable cache → signal error to caller.
                    if cache["domains"] is not None:
                        return cache["domains"]  # serve stale rather than false-clean
                    return None
                text = await resp.text()
                etag = resp.headers.get("ETag")

            domains: set = set()
            for line in text.splitlines():
                d = line.strip().lower()
                # Skip blanks / comments; keep only hostname-shaped lines.
                if not d or d.startswith("#"):
                    continue
                if re.fullmatch(r"[a-z0-9._\-]+\.[a-z]{2,}", d):
                    domains.add(d)
            cache["domains"] = domains
            cache["etag"] = etag
            cache["fetched_at"] = now
            return domains

    async def _query_phishing_database(
        self,
        session: aiohttp.ClientSession,
        domain: str,
        keywords: List[str],
        agent=None,
    ) -> List[Dict]:
        """Match the brand against the Phishing.Database ACTIVE feed (#1611).

        The FIRST live producer of `DarkWebSourceType.PHISHING_DATABASE` — our
        only phishing-URL threat surface (URLhaus is malware-distribution, a
        different threat model). A community-verified ACTIVE phishing domain
        that embeds the brand's registrable label is a confirmed brand-
        impersonation phishing vector.

        FP GATE — boundary-anchored, NEVER a bare substring. Each phishing
        domain is split into its `[.-]`-delimited segments (labels + hyphen
        parts); a brand term matches ONLY when it EQUALS a whole segment (the
        brand appears as a standalone label / hyphen-part), so a glued infix
        (the brand token concatenated inside a longer segment) does NOT fire.
        Measured on the real feed: raw substring `trade` = 316 hits,
        boundary-gated = 6. An un-gated match is a defect (the DRP HIGH queue
        was once ~94% false-positive from exactly this substring noise).

        Brand terms are the owned-domain registrable core + the brand keywords,
        length-gated (>= 4 chars) — a <4-char label match against a 391k-domain
        global feed is too collision-prone to be worth the FP cost (short-named
        brands are covered by the typosquat/lookalike surfaces instead). The
        emitted severity is a MEDIUM fallback only; the backend routes
        `source=PHISHING_DATABASE` to the 'impersonator' bucket (impersonation
        watch — surfaced, not auto-HIGH, so a phishing domain that shares a
        common brand token but targets a different brand does not flood HIGH).

        FREE, KEYLESS, MIT-licensed global feed → no ProviderQuotaService lease
        (RansomLook precedent). `_mark_source_status('phishing_database', ...)`
        on every exit path so a fetch failure reads ERROR, never a silent clean.
        """
        results: List[Dict] = []
        # #1617 — brand terms are the monitor's OWN registrable label ONLY.
        # `monitor.keywords` is free-text operator input (dark-web.service.ts)
        # and was the flood vector: a generic keyword matched thousands of
        # unrelated rows in a 391,616-domain global feed. Measured on the live
        # feed, matching keywords as domain segments yielded `link` 6,667 /
        # `mail` 5,483 / `site` 4,928 / `login` 3,423 / `shop` 3,313 hits —
        # none brand-related. Keyword-driven discovery belongs to the
        # typosquat/lookalike surfaces, which score for it; this leg answers
        # only "is MY registrable label embedded in an active phishing domain".
        brand_terms: List[str] = []
        seen_terms = set()
        domain_l = (domain or "").strip().lower()
        core = domain_l.split(".")[0] if domain_l else ""
        for candidate in [core]:
            c = (candidate or "").strip().lower()
            if len(c) >= 4 and c not in seen_terms:
                seen_terms.add(c)
                brand_terms.append(c)

        if not brand_terms:
            # No usable brand term (e.g. only a <4-char label) — nothing to
            # match, and the feed was never contacted. Leave UNMARKED so
            # scan-health does not misreport an un-run leg as clean.
            return results

        try:
            if agent:
                agent.report_progress(
                    f"Querying Phishing.Database ACTIVE feed for {domain}"
                )
            phishing_domains = await self._fetch_phishing_domains(session, agent)
            if phishing_domains is None:
                self._mark_source_status("phishing_database", "error")
                if agent:
                    agent.report_progress("Phishing.Database feed fetch failed")
                return results

            self._mark_source_status("phishing_database", "swept")

            term_set = set(brand_terms)
            matched_pairs = _match_phishing_domains(phishing_domains, term_set)
            matched_total = len(matched_pairs)
            matched_pairs = matched_pairs[:PHISHING_DB_MAX_EMISSIONS]
            truncated = matched_total > len(matched_pairs)
            if truncated:
                # #1617 — a silent cap reads downstream as "these are all the
                # matches". Say so on the record instead: the operator needs to
                # know the alphabetical tail was dropped.
                self._mark_source_status("phishing_database", "swept_truncated")
                if agent:
                    agent.report_progress(
                        f"Phishing.Database: {matched_total} matches capped to "
                        f"{PHISHING_DB_MAX_EMISSIONS} (alphabetical); "
                        f"{matched_total - len(matched_pairs)} not emitted"
                    )

            for pd, matched_term in matched_pairs:
                results.append(
                    {
                        "source": "PHISHING_DATABASE",
                        "sourceName": "Phishing.Database",
                        "sourceUrl": f"https://{pd}",
                        "sourceId": f"phishdb-{pd}",
                        "title": (
                            f"Active phishing domain impersonating {matched_term}: {pd}"
                        ),
                        "contentSnippet": (
                            f"The domain {pd} appears on the Phishing.Database ACTIVE "
                            f'feed (community-verified active phishing) and embeds the '
                            f'brand label "{matched_term}" as a domain segment. Likely '
                            f"brand-impersonation phishing — verify the domain targets "
                            f"this brand."
                        ),
                        "matchType": "BRAND_MENTION",
                        "matchedKeywords": [matched_term],
                        # Fallback only; the backend scorer bands this via the
                        # 'impersonator' bucket (MEDIUM). Never drives the alert.
                        "severity": "MEDIUM",
                        "relevanceScore": 70,
                        "riskScore": 60,
                        "discoveredAt": None,  # the feed carries no per-domain timestamp
                        "metadata": {
                            "vendor": "Phishing.Database",
                            "license": "MIT",
                            "feed": "phishing-domains-ACTIVE",
                            "phishingDomain": pd,
                            "matchedLabel": matched_term,
                            # #1617 — carry the cap on the record so a
                            # truncated sweep is never mistaken downstream for
                            # a complete one.
                            "matchedTotal": matched_total,
                            "truncated": truncated,
                        },
                    }
                )
            if agent and results:
                agent.report_progress(
                    f"Phishing.Database matched {len(results)} active phishing domain(s)"
                )
        except Exception as e:
            self._mark_source_status("phishing_database", "error")
            if agent:
                agent.report_progress(f"Phishing.Database query failed: {str(e)}")
        return results

    async def _query_hibp_breaches(
        self,
        session: aiohttp.ClientSession,
        domain: str,
        agent=None,
        extra_domains: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Query Have I Been Pwned for breaches associated with the domain.

        #889 — matches the monitor apex PLUS the tenant's owned/defensive-domain
        cohort (`extra_domains`). HIBP's free `/breaches` catalog is a SINGLE
        keyless GET of the entire breach list, so covering extra domains is a
        pure in-memory set-membership widening — it adds ZERO HTTP calls and no
        rate-limit pressure (unlike the LeakCheck leg).
        """
        results = []
        # HIBP-1 — build the exact-match apex SET: the monitored domain plus the
        # owned-domain cohort, each normalised to its apex (strip a leading
        # `www.`, which operators sometimes store) so an exact breach_domain
        # comparison doesn't miss a real breach on a www-prefixed input.
        def _apex(value: str) -> str:
            v = (value or '').lower().strip()
            return v[4:] if v.startswith('www.') else v

        monitored_apexes = {
            a for a in (_apex(d) for d in [domain] + list(extra_domains or [])) if a
        }
        try:
            if agent:
                agent.report_progress(
                    f"Querying HIBP for {len(monitored_apexes)} domain(s) breaches",
                )

            url = 'https://haveibeenpwned.com/api/v3/breaches'
            headers = {'User-Agent': 'ASM-Platform-DarkWebMonitor'}
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    breaches = await resp.json()
                    for breach in breaches:
                        breach_domain = breach.get('Domain', '').lower()

                        # HIBP-1 — EXACT domain-scoped match only. The old
                        # `domain.split('.')[0] in breach_name` substring disjunct
                        # minted cross-brand CREDENTIAL_LEAKs (with an SLA clock)
                        # for any brand label that is merely a substring of an
                        # unrelated breach name ('sol' in 'solarwinds'). The free
                        # /breaches catalog carries each breach's Domain, so trust
                        # only an exact apex match — now against the owned-domain
                        # SET (#889), still exact, never a substring.
                        if breach_domain and breach_domain in monitored_apexes:
                            data_classes = breach.get('DataClasses', [])
                            has_passwords = 'Passwords' in data_classes
                            pwn_count = breach.get('PwnCount', 0)

                            severity = 'CRITICAL' if has_passwords and pwn_count > 100000 else 'HIGH' if has_passwords else 'MEDIUM'

                            results.append({
                                'source': 'CREDENTIAL_DUMP',
                                'sourceName': 'Have I Been Pwned',
                                'sourceUrl': f"https://haveibeenpwned.com/api/v3/breach/{breach.get('Name', '')}",
                                'sourceId': f"hibp-{breach.get('Name', '')}",
                                'title': f"Data breach: {breach.get('Title', breach.get('Name', domain))}",
                                'contentSnippet': f"Breach '{breach.get('Title', '')}' on {breach.get('BreachDate', 'unknown date')}. {pwn_count:,} accounts affected. Exposed data: {', '.join(data_classes[:10])}. Verified: {breach.get('IsVerified', False)}",
                                'matchType': 'CREDENTIAL_LEAK',
                                # #889 — the actually-matched apex (may be an
                                # owned domain, not the monitor apex).
                                'matchedKeywords': [breach_domain],
                                'severity': severity,
                                'relevanceScore': 90,  # exact apex match only (HIBP-1)
                                'riskScore': 85 if has_passwords else 65,
                                'discoveredAt': breach.get('AddedDate', breach.get('BreachDate', None)),
                                'metadata': {
                                    'breachName': breach.get('Name'),
                                    'breachDate': breach.get('BreachDate'),
                                    'matchedDomain': breach_domain,
                                    'pwnCount': pwn_count,
                                    'dataClasses': data_classes,
                                    'isVerified': breach.get('IsVerified', False),
                                    'isSensitive': breach.get('IsSensitive', False),
                                    'hasPasswords': has_passwords,
                                }
                            })
        except Exception as e:
            if agent:
                agent.report_progress(f"HIBP query failed: {str(e)}")
        return results

    async def _query_intelx(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query IntelX.io for credential leaks and breach data.

        Free tier (no API key): Uses Phonebook API for email enumeration.
        Pro tier (INTELX_API_KEY set): Uses Intelligent Search for deeper results.

        DRP→ASM T2.8c: per-tenant lease via ProviderQuotaService.checkout for
        INTELX. The lease covers a single logical IntelX query — whether it
        runs as phonebook (free) or intelligent-search (pro), and whether pro
        falls back to phonebook on 402. One operation == one lease.
        Falls back to INTELX_API_KEY env when no integration is configured.

        Feature-flagged via ENABLE_INTELX (default off — DRP locked-decision
        #5). When disabled, returns [] immediately without leasing or
        calling IntelX.
        """
        results: List[Dict] = []

        if not ENABLE_INTELX:
            if agent:
                agent.report_progress(
                    "IntelX query skipped: ENABLE_INTELX is off (set ENABLE_INTELX=true to enable)"
                )
            return results

        # Lease INTELX quota up front.
        lease_token: Optional[str] = None
        api_key = ''
        try:
            lease = await checkout_provider('INTELX', requested_units=1)
            api_key = lease.get('apiKey') or ''
            lease_token = lease.get('leaseToken')
        except QuotaExceededError as e:
            if agent:
                agent.report_progress(
                    f"IntelX quota exceeded: retry in {e.retry_after}s"
                )
            return results
        except IntegrationCredentialsError:
            api_key = os.environ.get('INTELX_API_KEY', '')

        ix_success = False
        ix_error_code: Optional[str] = None
        try:
            if agent:
                agent.report_progress(f"Querying IntelX.io for {domain}")

            base_url = 'https://2.intelx.io'

            if api_key:
                # Pro tier: Intelligent Search API
                results = await self._query_intelx_pro(session, base_url, api_key, domain, agent)
            else:
                # Free tier: Phonebook API (no key required)
                results = await self._query_intelx_phonebook(session, base_url, domain, agent)

            if agent and results:
                agent.report_progress(f"IntelX found {len(results)} results for {domain}")
            ix_success = True
        except Exception as e:
            ix_error_code = type(e).__name__
            if agent:
                agent.report_progress(f"IntelX query failed: {str(e)}")
        finally:
            if lease_token:
                await reconcile_call(
                    'INTELX',
                    lease_token,
                    units=1,
                    success=ix_success,
                    error_code=ix_error_code,
                )
        return results

    async def _query_intelx_phonebook(self, session: aiohttp.ClientSession, base_url: str, domain: str, agent=None) -> List[Dict]:
        """Free tier: Phonebook API for email enumeration on the domain."""
        results = []
        try:
            # Start phonebook search
            search_url = f'{base_url}/phonebook/search'
            params = {
                'term': domain,
                'maxresults': 50,
                'media': 0,  # 0 = all
                'target': 1,  # 1 = emails
            }
            async with session.get(search_url, params=params) as resp:
                if resp.status != 200:
                    if agent:
                        agent.report_progress(f"IntelX Phonebook search returned status {resp.status}")
                    return results
                data = await resp.json()
                search_id = data.get('id')
                if not search_id:
                    return results

            # Wait briefly then fetch results
            await asyncio.sleep(2)

            result_url = f'{base_url}/phonebook/search/result'
            params = {'id': search_id, 'limit': 50, 'offset': 0}
            async with session.get(result_url, params=params) as resp:
                if resp.status != 200:
                    return results
                data = await resp.json()
                selectors = data.get('selectors', [])

                for sel in selectors[:30]:
                    selector_value = sel.get('selectorvalue', '')
                    selector_type = sel.get('selectortypeh', '')

                    if '@' in selector_value and domain.lower() in selector_value.lower():
                        results.append({
                            'source': 'CREDENTIAL_DUMP',
                            'sourceName': 'IntelX.io (Phonebook)',
                            'sourceUrl': f'https://intelx.io/?s={domain}',
                            'sourceId': f"intelx-pb-{hashlib.sha256(selector_value.encode()).hexdigest()[:12]}",
                            'title': f"Email found in breach databases: {selector_value}",
                            'contentSnippet': f"Email address {selector_value} associated with {domain} was found in IntelX.io phonebook search across breach databases and paste sites. Type: {selector_type}.",
                            'matchType': 'CREDENTIAL_LEAK',
                            'matchedKeywords': [domain, selector_value],
                            'severity': 'HIGH',
                            'relevanceScore': 80,
                            'riskScore': 75,
                            'discoveredAt': None,
                            'metadata': {
                                'email': selector_value,
                                'selectorType': selector_type,
                                'breachSource': 'IntelX Phonebook',
                                'tier': 'free',
                            }
                        })
        except Exception as e:
            if agent:
                agent.report_progress(f"IntelX Phonebook query failed: {str(e)}")
        return results

    async def _query_intelx_pro(self, session: aiohttp.ClientSession, base_url: str, api_key: str, domain: str, agent=None) -> List[Dict]:
        """Pro tier: Intelligent Search API for deeper breach data."""
        results = []
        headers = {'x-key': api_key}
        try:
            # Start intelligent search
            search_url = f'{base_url}/intelligent/search'
            payload = {
                'term': domain,
                'maxresults': 50,
                'media': 0,
                'sort': 2,  # sort by relevance
                'terminate': [None],
            }
            async with session.post(search_url, json=payload, headers=headers) as resp:
                if resp.status == 402:
                    if agent:
                        agent.report_progress("IntelX API key has insufficient credits, falling back to free tier")
                    return await self._query_intelx_phonebook(session, base_url, domain, agent)
                if resp.status != 200:
                    if agent:
                        agent.report_progress(f"IntelX Intelligent Search returned status {resp.status}")
                    return results
                data = await resp.json()
                search_id = data.get('id')
                if not search_id:
                    return results

            # Wait then fetch results
            await asyncio.sleep(3)

            result_url = f'{base_url}/intelligent/search/result'
            params = {'id': search_id, 'limit': 50, 'offset': 0}
            async with session.get(result_url, params=params, headers=headers) as resp:
                if resp.status != 200:
                    return results
                data = await resp.json()
                records = data.get('records', [])

                for record in records[:30]:
                    name = record.get('name', '')
                    media_type = record.get('mediah', 'unknown')
                    bucket = record.get('bucketh', 'unknown')
                    added = record.get('added', None)
                    system_id = record.get('systemid', '')

                    # Determine severity based on media type
                    severity = 'HIGH'
                    match_type = 'CREDENTIAL_LEAK'
                    if 'paste' in media_type.lower():
                        match_type = 'PASTE_SITE'
                        severity = 'MEDIUM'
                    elif 'leak' in bucket.lower() or 'breach' in bucket.lower():
                        severity = 'CRITICAL'
                    elif 'darknet' in bucket.lower() or 'tor' in bucket.lower():
                        match_type = 'DARK_WEB_MENTION'
                        severity = 'HIGH'

                    results.append({
                        'source': 'CREDENTIAL_DUMP',
                        'sourceName': f'IntelX.io ({bucket})',
                        'sourceUrl': f'https://intelx.io/?s={domain}',
                        'sourceId': f"intelx-{system_id[:12] if system_id else hashlib.sha256(name.encode()).hexdigest()[:12]}",
                        'title': f"Breach data found: {name[:100] if name else domain}",
                        'contentSnippet': f"Found in IntelX.io {bucket} database. Media type: {media_type}. Source: {name[:200]}. This record may contain credentials, PII, or sensitive data associated with {domain}.",
                        'matchType': match_type,
                        'matchedKeywords': [domain],
                        'severity': severity,
                        'relevanceScore': 85,
                        'riskScore': 80 if severity in ['CRITICAL', 'HIGH'] else 65,
                        'discoveredAt': added,
                        'metadata': {
                            'breachSource': bucket,
                            'mediaType': media_type,
                            'systemId': system_id,
                            'name': name[:200],
                            'tier': 'pro',
                        }
                    })
        except Exception as e:
            if agent:
                agent.report_progress(f"IntelX Intelligent Search failed: {str(e)}")
        return results

    def _load_simulation_data(self, domain: str, keywords: List[str]) -> List[Dict]:
        """Load simulation data from JSON file and replace placeholders"""
        try:
            data_path = Path(__file__).parent / 'data' / 'darkweb_sample_data.json'
            with open(data_path, 'r') as f:
                data = json.load(f)

            mentions = data.get('mentions', [])
            results = []
            for mention in mentions:
                # Deep copy and replace placeholders
                entry = json.loads(json.dumps(mention))
                for key in ['title', 'contentSnippet', 'sourceUrl']:
                    if key in entry and isinstance(entry[key], str):
                        entry[key] = entry[key].replace('{{domain}}', domain)

                # Replace keywords in matchedKeywords
                if 'matchedKeywords' in entry:
                    entry['matchedKeywords'] = [
                        kw.replace('{{domain}}', domain) for kw in entry['matchedKeywords']
                    ]

                # Add simulation flag
                if not entry.get('metadata'):
                    entry['metadata'] = {}
                entry['metadata']['simulation'] = True

                results.append(entry)

            return results
        except Exception as e:
            logger.warning(f"[DarkWebMonitor] Failed to load simulation data: {e}")
            return []


def get_tool():
    return DarkWebMonitorTool()
