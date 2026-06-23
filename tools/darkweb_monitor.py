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
import urllib.parse
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

try:
    from playwright.async_api import async_playwright
except Exception:
    async_playwright = None


# OTX and IntelX are out of the DRP migration vendor scope (locked-decision
# #5; only HikerAPI / ScrapeCreators / twitterapi.io are in scope). The
# integrations stay in the codebase for non-DRP use cases but default OFF —
# operators must set ENABLE_OTX=true / ENABLE_INTELX=true explicitly to
# re-enable. With the flag off, _query_otx / _query_intelx short-circuit to
# an empty result list before any HTTP work (so no leases consumed, no
# vendor calls).
ENABLE_OTX = os.environ.get("ENABLE_OTX", "false").lower() in ("true", "1", "yes")
ENABLE_INTELX = os.environ.get("ENABLE_INTELX", "false").lower() in ("true", "1", "yes")


class DarkWebMonitorTool(ToolPlugin):
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
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Sources to query (default: all). Options: urlhaus, otx, github, gitlab, bitbucket, npm, stackoverflow, pastebin, leakcheck, threatfox, hibp, intelx, onion_forums, simulation"
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

    def _extract_search_terms(self, domain: str, patterns: List[Dict[str, Any]]) -> List[str]:
        terms: List[str] = []
        seen = set()

        def add_term(value: str) -> None:
            normalized = str(value or '').strip()
            if not normalized:
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
        )
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
                await browser.close()

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
            'bitbucket',
            'npm',
            'stackoverflow',
            'pastebin',
            'leakcheck',
            'threatfox',
            'hibp',
            'intelx',
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
                tasks.append(self._query_github(session, domain, normalized_patterns, agent))
            if 'gitlab' in sources:
                tasks.append(self._query_gitlab(session, domain, normalized_patterns, agent))
            if 'bitbucket' in sources:
                tasks.append(self._query_bitbucket(session, domain, normalized_patterns, agent))
            if 'npm' in sources:
                tasks.append(self._query_npm(session, domain, normalized_patterns, agent))
            if 'stackoverflow' in sources:
                tasks.append(self._query_stackoverflow(session, domain, normalized_patterns, agent))
            if 'pastebin' in sources:
                tasks.append(self._query_pastebin(session, domain, normalized_patterns, agent))
            if 'threatfox' in sources:
                tasks.append(self._query_threatfox(session, domain, agent))
            if 'hibp' in sources:
                tasks.append(self._query_hibp_breaches(session, domain, agent))
            if 'intelx' in sources:
                tasks.append(self._query_intelx(session, domain, agent))
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
                    lc_results = await self._query_leakcheck(session, domain, agent)
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

    async def _query_urlhaus(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query abuse.ch URLhaus for domain mentions"""
        results = []
        try:
            if agent:
                agent.report_progress(f"Querying URLhaus for {domain}")

            url = 'https://urlhaus-api.abuse.ch/v1/host/'
            async with session.post(url, data={'host': domain}) as resp:
                if resp.status == 200:
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
        """
        results: List[Dict] = []

        if not ENABLE_OTX:
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
            if agent:
                agent.report_progress(f"OTX quota exceeded: retry in {e.retry_after}s")
            return results
        except IntegrationCredentialsError:
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
            resp = await asyncio.wait_for(
                upstream_request(
                    session, 'GET', url,
                    headers=headers,
                    provider_label='darkweb:otx',
                ),
                timeout=20,
            )
            if resp.status == 200:
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
            otx_success = True
        except asyncio.TimeoutError:
            otx_error_code = 'TimeoutError'
            if agent:
                agent.report_progress("OTX query timed out after 20s")
        except Exception as e:
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

    async def _query_github(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        """Search GitHub repositories and code for brand mentions and exposed secrets.

        DRP→ASM T2.8c: per-tenant lease via ProviderQuotaService.checkout for
        GITHUB_SEARCH. Falls back to GITHUB_TOKEN env var if no integration
        is configured. Reconciles with the actual number of API calls made
        (repo search + code search × terms).
        """
        results = []

        # Lease GITHUB_SEARCH quota up front. The github_token from the lease
        # supersedes the env var when present.
        lease_token: Optional[str] = None
        github_token = ''
        try:
            lease = await checkout_provider('GITHUB_SEARCH', requested_units=1)
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
                repo_url = f'https://api.github.com/search/repositories?q={repo_query}&sort=updated&order=desc&per_page=8'
                async with session.get(repo_url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get('items', [])
                        for item in items[:5]:
                            repo = item or {}
                            description = repo.get('description') or ''
                            matched_keywords = self._text_matches_search_terms(
                                f"{repo.get('full_name', '')} {description}",
                                patterns,
                                'CODE_REPOSITORY',
                            ) or [search_term]
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

            search_queries = []
            for term in search_terms[:4]:
                quoted = f'"{term}"'
                search_queries.extend([
                    (term, f'{quoted} password OR secret OR api_key OR token'),
                    (term, f'{quoted} leak OR credential OR dump'),
                ])

            for search_term, query in search_queries:
                url = f'https://api.github.com/search/code?q={query}&per_page=10'
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get('items', [])
                        for item in items[:5]:
                            repo = item.get('repository', {})
                            results.append({
                                'source': 'CODE_REPOSITORY',
                                'sourceName': f"GitHub - {repo.get('full_name', 'unknown')}",
                                'sourceUrl': item.get('html_url', ''),
                                'sourceId': f"github-{item.get('sha', '')[:12]}",
                                'title': f"Potential exposed secret in {repo.get('full_name', 'unknown')}",
                                'contentSnippet': f"Code search term '{search_term}' matched in {item.get('path', 'unknown file')} in repository {repo.get('full_name', 'unknown')}. This may contain exposed credentials, leak references, or API keys associated with {domain}.",
                                'matchType': 'EXPOSED_SECRET',
                                'matchedKeywords': [domain, search_term] if search_term != domain else [domain],
                                'severity': 'HIGH',
                                'relevanceScore': 75,
                                'riskScore': 70,
                                'discoveredAt': None,
                                'metadata': {
                                    'repository': repo.get('full_name'),
                                    'path': item.get('path'),
                                    'sha': item.get('sha'),
                                    'searchTerm': search_term,
                                }
                            })
                    elif resp.status == 403:
                        if agent:
                            agent.report_progress("GitHub API rate limit reached")
                        break

                await asyncio.sleep(2)  # Rate limiting

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
                    units=1,
                    success=success,
                    error_code=error_code,
                )
        return results

    async def _query_gitlab(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        results = []
        try:
            if agent:
                agent.report_progress(f"Searching GitLab for {domain}")

            for search_term in self._extract_search_terms(domain, patterns)[:4]:
                async with session.get(
                    'https://gitlab.com/api/v4/projects',
                    params={
                        'search': search_term,
                        'simple': 'true',
                        'order_by': 'last_activity_at',
                        'sort': 'desc',
                        'per_page': 8,
                    },
                ) as resp:
                    if resp.status != 200:
                        continue
                    projects = await resp.json()
                    for project in projects[:5]:
                        description = project.get('description') or ''
                        results.append({
                            'source': 'CODE_REPOSITORY',
                            'sourceName': 'GitLab',
                            'sourceUrl': project.get('web_url', ''),
                            'sourceId': f"gitlab-{project.get('id', '')}",
                            'title': project.get('path_with_namespace') or project.get('name', f'GitLab project matching {search_term}'),
                            'contentSnippet': description or f"Public GitLab project matching '{search_term}'",
                            'matchType': 'BRAND_MENTION',
                            'matchedKeywords': self._text_matches_search_terms(
                                f"{project.get('path_with_namespace', '')} {description}",
                                patterns,
                                'CODE_REPOSITORY',
                            ) or [search_term],
                            'severity': 'LOW',
                            'relevanceScore': 68,
                            'riskScore': 45,
                            'discoveredAt': project.get('last_activity_at') or project.get('created_at'),
                            'metadata': {
                                'namespace': project.get('namespace', {}).get('full_path'),
                                'visibility': project.get('visibility'),
                                'searchTerm': search_term,
                            }
                        })
                await asyncio.sleep(0.5)
        except Exception as e:
            if agent:
                agent.report_progress(f"GitLab search failed: {str(e)}")
        return results

    async def _query_bitbucket(self, session: aiohttp.ClientSession, domain: str, patterns: List[Dict[str, Any]], agent=None) -> List[Dict]:
        results = []
        try:
            if agent:
                agent.report_progress(f"Searching Bitbucket for {domain}")

            for search_term in self._extract_search_terms(domain, patterns)[:3]:
                query = f'name~"{search_term}" OR description~"{search_term}"'
                async with session.get(
                    'https://api.bitbucket.org/2.0/repositories',
                    params={'q': query, 'sort': '-updated_on', 'pagelen': 8},
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()
                    for repo in data.get('values', [])[:5]:
                        description = repo.get('description') or ''
                        results.append({
                            'source': 'CODE_REPOSITORY',
                            'sourceName': 'Bitbucket',
                            'sourceUrl': repo.get('links', {}).get('html', {}).get('href', ''),
                            'sourceId': f"bitbucket-{repo.get('uuid', '')}",
                            'title': repo.get('full_name') or repo.get('name', f'Bitbucket repository matching {search_term}'),
                            'contentSnippet': description or f"Public Bitbucket repository matching '{search_term}'",
                            'matchType': 'BRAND_MENTION',
                            'matchedKeywords': self._text_matches_search_terms(
                                f"{repo.get('full_name', '')} {description}",
                                patterns,
                                'CODE_REPOSITORY',
                            ) or [search_term],
                            'severity': 'LOW',
                            'relevanceScore': 64,
                            'riskScore': 42,
                            'discoveredAt': repo.get('updated_on') or repo.get('created_on'),
                            'metadata': {
                                'workspace': repo.get('workspace', {}).get('name'),
                                'isPrivate': repo.get('is_private'),
                                'searchTerm': search_term,
                            }
                        })
                await asyncio.sleep(0.5)
        except Exception as e:
            if agent:
                agent.report_progress(f"Bitbucket search failed: {str(e)}")
        return results

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
                        results.append({
                            'source': 'CODE_REPOSITORY',
                            'sourceName': 'npm',
                            'sourceUrl': pkg.get('links', {}).get('npm', ''),
                            'sourceId': f"npm-{name}",
                            'title': name or f'npm package matching {search_term}',
                            'contentSnippet': description or f"Public npm package matching '{search_term}'",
                            'matchType': 'BRAND_MENTION',
                            'matchedKeywords': self._text_matches_search_terms(
                                f"{name} {description}",
                                patterns,
                                'CODE_REPOSITORY',
                            ) or [search_term],
                            'severity': 'LOW',
                            'relevanceScore': 60,
                            'riskScore': 38,
                            'discoveredAt': pkg.get('date'),
                            'metadata': {
                                'version': pkg.get('version'),
                                'author': (pkg.get('author') or {}).get('name'),
                                'searchTerm': search_term,
                            }
                        })
                await asyncio.sleep(0.3)
        except Exception as e:
            if agent:
                agent.report_progress(f"npm search failed: {str(e)}")
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
                    },
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()
                    for item in data.get('items', [])[:5]:
                        title = item.get('title', f'Stack Overflow mention for {search_term}')
                        tags = item.get('tags', [])
                        results.append({
                            'source': 'CODE_REPOSITORY',
                            'sourceName': 'Stack Overflow',
                            'sourceUrl': item.get('link', ''),
                            'sourceId': f"stackoverflow-{item.get('question_id', '')}",
                            'title': title,
                            'contentSnippet': f"Public Stack Overflow discussion tagged {', '.join(tags[:5]) or 'general'} matching '{search_term}'",
                            'matchType': 'TARGETING_DISCUSSION',
                            'matchedKeywords': self._text_matches_search_terms(
                                f"{title} {' '.join(tags)}",
                                patterns,
                                'CODE_REPOSITORY',
                            ) or [search_term],
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
                        })
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
                    if agent:
                        agent.report_progress(f"Pastebin scrape returned status {resp.status}")
                    return results
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
                return {
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
                }

            inspected = await asyncio.gather(
                *(inspect_paste(entry) for entry in (pastes or [])[:40]),
                return_exceptions=True,
            )
            for item in inspected:
                if isinstance(item, dict):
                    results.append(item)
        except Exception as e:
            if agent:
                agent.report_progress(f"Pastebin search failed: {str(e)}")
        return results

    # 2026-05-16 — _query_searxng() removed. SearxNG decommissioned. Stale
    # SearxNG-tagged DarkWebMention rows were purged in the same commit.
    # The native github / gitlab / npm / stackoverflow queries (_query_github
    # etc. above) provide direct coverage of the engines SearxNG was
    # meta-searching across, so no functionality is lost.

    async def _query_leakcheck(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query LeakCheck public API for credential leaks"""
        results = []
        prefixes = ['info', 'admin', 'support', 'hr', 'sales', 'security', 'noreply', 'contact', 'help', 'billing']
        try:
            if agent:
                agent.report_progress(f"Querying LeakCheck for {domain} credential leaks")

            for prefix in prefixes:
                email = f"{prefix}@{domain}"
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
                                        'matchedKeywords': [domain, email],
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
                            if agent:
                                agent.report_progress("LeakCheck rate limited, stopping")
                            break
                except Exception as e:
                    if agent:
                        agent.report_progress(f"LeakCheck query for {email} failed: {str(e)}")
                await asyncio.sleep(1)  # Rate limit: 1 req/sec

            if agent and results:
                agent.report_progress(f"LeakCheck found {len(results)} credential leaks")
        except Exception as e:
            if agent:
                agent.report_progress(f"LeakCheck query failed: {str(e)}")
        return results

    async def _query_threatfox(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query ThreatFox (abuse.ch) for IOC data"""
        results = []
        try:
            if agent:
                agent.report_progress(f"Querying ThreatFox for {domain}")

            url = 'https://threatfox-api.abuse.ch/api/v1/'
            payload = {"query": "search_ioc", "search_term": domain}
            async with session.post(url, json=payload) as resp:
                if resp.status == 200:
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
            if agent:
                agent.report_progress(f"ThreatFox query failed: {str(e)}")
        return results

    async def _query_hibp_breaches(self, session: aiohttp.ClientSession, domain: str, agent=None) -> List[Dict]:
        """Query Have I Been Pwned for breaches associated with the domain"""
        results = []
        try:
            if agent:
                agent.report_progress(f"Querying HIBP for {domain} breaches")

            url = 'https://haveibeenpwned.com/api/v3/breaches'
            headers = {'User-Agent': 'ASM-Platform-DarkWebMonitor'}
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    breaches = await resp.json()
                    for breach in breaches:
                        breach_domain = breach.get('Domain', '').lower()
                        breach_name = breach.get('Name', '').lower()

                        # Match if the domain field matches OR domain appears in breach name
                        if breach_domain == domain.lower() or domain.lower().split('.')[0] in breach_name:
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
                                'matchedKeywords': [domain],
                                'severity': severity,
                                'relevanceScore': 90 if breach_domain == domain.lower() else 60,
                                'riskScore': 85 if has_passwords else 65,
                                'discoveredAt': breach.get('AddedDate', breach.get('BreachDate', None)),
                                'metadata': {
                                    'breachName': breach.get('Name'),
                                    'breachDate': breach.get('BreachDate'),
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
