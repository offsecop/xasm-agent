"""
Brand VIP exposure monitoring tool.

Uses public search results to look for social profiles, impersonation attempts,
targeting signals, and exposure mentions tied to a registered VIP.
"""

import asyncio
import hashlib
import os
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
    'CONTACT_EXPOSURE': [
        'email', 'phone', 'address', 'contact', 'mobile', 'leak', 'breach',
        'dox', 'doxx', 'exposed', 'paste',
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


def _extract_title(html: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', html or '', re.IGNORECASE | re.DOTALL)
    if not match:
        return ''
    return _normalize_spaces(unescape(re.sub(r'<[^>]+>', '', match.group(1))))


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
    results: List[Dict[str, str]] = []
    blocks = re.findall(
        r'<div[^>]+class="[^"]*result[^"]*"[^>]*>(.*?)</div>\s*</div>',
        html or '',
        flags=re.IGNORECASE | re.DOTALL,
    )

    if not blocks:
        blocks = re.findall(
            r'<a[^>]+class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>(.{0,1400})',
            html or '',
            flags=re.IGNORECASE | re.DOTALL,
        )
        for href, title_html, tail in blocks:
            snippet_match = re.search(
                r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>',
                tail,
                flags=re.IGNORECASE | re.DOTALL,
            )
            results.append({
                'url': _unwrap_search_url(href),
                'title': _strip_html(title_html),
                'content': _strip_html(snippet_match.group(1) if snippet_match else ''),
            })
            if len(results) >= max_results:
                return results
        return results

    for block in blocks:
        link_match = re.search(
            r'<a[^>]+class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            block,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not link_match:
            continue
        snippet_match = re.search(
            r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>',
            block,
            flags=re.IGNORECASE | re.DOTALL,
        )
        results.append({
            'url': _unwrap_search_url(link_match.group(1)),
            'title': _strip_html(link_match.group(2)),
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

    return {
        'findingHash': finding_hash,
        'platform': platform,
        'sourceName': source_name,
        'sourceUrl': profile_url,
        'title': page_title or f'Known {source_name} profile for {full_name}',
        'contentSnippet': (
            f'{full_name} has a registered public profile URL that can be tracked '
            f'for impersonation, account changes, and exposure signals.'
        ),
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
        },
    }


def _classify_exposure(
    platform: str,
    title: str,
    snippet: str,
    url: str,
    full_name: str,
    company_name: str,
    company_domain: str,
) -> Dict[str, Any]:
    haystack = _normalize_spaces(f"{title} {snippet} {url}").lower()
    exact_name = full_name.lower() in haystack
    company_match = False
    for token in _company_tokens(company_name, company_domain):
        if token in haystack:
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
        for keyword in EXPOSURE_KEYWORDS['CONTACT_EXPOSURE']:
            if keyword in haystack:
                exposure_type = 'CONTACT_EXPOSURE'
                severity = 'HIGH'
                risk_score = 78
                confidence = 0.8
                break

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
        email = _normalize_spaces(parameters.get('email', ''))
        profile_urls = _extract_profile_urls(parameters)
        max_results = int(parameters.get('maxResults', 15) or 15)

        searxng_url = os.environ.get('SEARXNG_URL', '').strip()

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

        queries: List[str] = []
        exact_name = f'"{full_name}"'
        company_hint = company_name or company_domain
        if company_hint:
            queries.extend([
                f'{exact_name} "{company_hint}" site:linkedin.com/in',
                f'{exact_name} "{company_hint}" site:x.com',
                f'{exact_name} "{company_hint}" site:twitter.com',
                f'{exact_name} "{company_hint}" site:instagram.com',
                f'{exact_name} "{company_hint}"',
                f'{exact_name} "{company_hint}" (leak OR breach OR dox OR exposed)',
                f'{exact_name} "{company_hint}" (fake OR impersonation OR parody OR scam)',
            ])
        else:
            queries.extend([
                f'{exact_name} site:linkedin.com/in',
                f'{exact_name} site:x.com',
                f'{exact_name} site:instagram.com',
                exact_name,
            ])

        if title and company_hint:
            queries.append(f'{exact_name} "{title}" "{company_hint}"')
        if email:
            queries.append(f'"{email}" "{full_name}"')
        for profile_url in profile_urls:
            queries.append(f'"{profile_url}"')

        unique_queries = list(dict.fromkeys([query for query in queries if query.strip()]))[:8]

        if agent:
            agent.report_progress(
                current_operation=f"Monitoring exposure for {full_name}",
                current_target=company_hint or full_name,
                items_processed=0,
                total_items=len(unique_queries),
            )

        findings: List[Dict[str, Any]] = []
        seen_hashes = set()
        search_diagnostics = {
            'searxngConfigured': bool(searxng_url),
            'queriesRun': 0,
            'resultsSeen': 0,
            'emptyResultQueries': 0,
            'failedQueries': 0,
            'publicSearchConfigured': os.environ.get('VIP_EXPOSURE_PUBLIC_SEARCH', 'true').lower() != 'false',
            'publicSearchQueriesRun': 0,
            'publicSearchResultsSeen': 0,
            'publicSearchFailedQueries': 0,
        }

        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout, headers=DEFAULT_HEADERS) as session:
            for profile_url in profile_urls:
                validation: Dict[str, Any] = {}
                try:
                    async with session.get(profile_url, allow_redirects=True) as resp:
                        body = await resp.text(errors='ignore')
                        validation = {
                            'reachable': resp.status < 500,
                            'httpStatus': resp.status,
                            'finalUrl': str(resp.url),
                            'title': _extract_title(body[:200000]),
                        }
                except Exception as exc:
                    validation = {
                        'reachable': False,
                        'error': str(exc),
                        'finalUrl': profile_url,
                    }

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

            if searxng_url:
                for index, query in enumerate(unique_queries):
                    try:
                        search_diagnostics['queriesRun'] += 1
                        engines = os.environ.get('VIP_EXPOSURE_SEARXNG_ENGINES', '').strip()
                        params = {
                            'q': query,
                            'format': 'json',
                            'safesearch': 0,
                            'language': 'en-US',
                        }
                        if engines:
                            params['engines'] = engines

                        async with session.get(searxng_url, params=params) as resp:
                            if resp.status != 200:
                                search_diagnostics['failedQueries'] += 1
                                continue
                            data = await resp.json()
                    except Exception as exc:
                        search_diagnostics['failedQueries'] += 1
                        if agent:
                            agent.append_output(f"[VipExposure] Search failed for query '{query}': {exc}")
                        continue

                    results = data.get('results', [])
                    if not results:
                        search_diagnostics['emptyResultQueries'] += 1
                    search_diagnostics['resultsSeen'] += len(results)

                    for item in results[:8]:
                        source_url = item.get('url', '') or ''
                        title_text = unescape(item.get('title', '') or '')
                        snippet = unescape(item.get('content', '') or item.get('description', '') or '')
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

                        finding = {
                            'findingHash': finding_hash,
                            'platform': platform,
                            'sourceName': platform.title() if platform != 'WEB' else 'Web Search',
                            'sourceUrl': source_url,
                            'title': title_text or f'{platform.title()} result for {full_name}',
                            'contentSnippet': snippet[:500],
                            'exposureType': classification['exposureType'],
                            'severity': classification['severity'],
                            'riskScore': classification['riskScore'],
                            'confidenceScore': classification['confidenceScore'],
                            'status': 'NEW',
                            'matchedKeywords': [token for token in [full_name, company_name or company_domain, title] if token],
                            'discoveredAt': item.get('publishedDate') or item.get('published_date'),
                            'metadata': {
                                'query': query,
                                'companyMatched': classification['companyMatched'],
                                'exactNameMatched': classification['exactNameMatched'],
                                'engine': 'searxng',
                                'searchEngine': item.get('engine'),
                            },
                        }
                        findings.append(finding)

                    if agent:
                        agent.report_progress(
                            current_operation="Searching public profiles and mentions",
                            current_target=query,
                            items_processed=index + 1,
                            total_items=len(unique_queries),
                        )

                    await asyncio.sleep(0.25)
            elif agent:
                agent.append_output("[VipExposure] SEARXNG_URL is not configured; direct profile checks only")

            if search_diagnostics['publicSearchConfigured']:
                public_queries = [
                    f'{full_name} {company_hint}'.strip(),
                    f'{full_name} {company_hint} linkedin'.strip(),
                    f'{full_name} {company_hint} email phone'.strip(),
                ]
                public_queries = list(dict.fromkeys([query for query in public_queries if query]))[:3]
                for query in public_queries:
                    try:
                        search_diagnostics['publicSearchQueriesRun'] += 1
                        async with session.get(
                            'https://html.duckduckgo.com/html/',
                            params={'q': query},
                        ) as resp:
                            if resp.status != 200:
                                search_diagnostics['publicSearchFailedQueries'] += 1
                                continue
                            html = await resp.text(errors='ignore')
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

                        findings.append({
                            'findingHash': finding_hash,
                            'platform': platform,
                            'sourceName': platform.title() if platform != 'WEB' else 'Public Web Search',
                            'sourceUrl': source_url,
                            'title': title_text or f'Public result for {full_name}',
                            'contentSnippet': snippet[:500],
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
                            },
                        })

                    await asyncio.sleep(0.35)

        findings.sort(key=lambda item: (item['riskScore'], item['confidenceScore']), reverse=True)
        findings = findings[:max_results]

        if agent:
            agent.append_output(
                f"[VipExposure] {full_name}: collected {len(findings)} finding(s) from {len(unique_queries)} search query(ies)"
            )

        return {
            'success': True,
            'output': {
                'brandVipId': brand_vip_id,
                'brandMonitorId': brand_monitor_id,
                'fullName': full_name,
                'findings': findings,
                'queriesRun': len(unique_queries),
                'searchDiagnostics': search_diagnostics,
            },
        }


def get_tool():
    return BrandMonitorVipExposureTool()
