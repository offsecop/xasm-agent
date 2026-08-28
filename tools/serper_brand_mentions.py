"""Serper.dev Brand-Mention Collection Tool — Brand Sentiment coverage (epic #873).

Implements `serper:brand_mentions` — surfaces PUBLIC brand mentions from
Google results (news / blogs / review + complaint sites) into the sentiment
pipeline. This is deliberately a SEPARATE tool from
`brand:monitor_vip_exposure`: that tool is per-VIP threat hunting
(impersonation / PII / credential dorks) with suppression tuned for FP
control; this one is brand-level mention COLLECTION where review/news hosts
are the SIGNAL, not noise, so the VIP tool's KNOWN_DIRECTORY_HOSTS
suppression deliberately does NOT apply here.

Quota discipline: every metered page goes through the shared
`lib/serper_search.dispatch_serper` (ProviderQuotaService checkout → POST →
reconcile, one bracket per page) — the same seam the VIP tool uses. A hard
per-scan page cap bounds worst-case spend.

Honesty notes:
  - SERP snippets are SHORT — a weaker sentiment signal than a full post
    body. Accepted: the alternative is zero web coverage.
  - Serper's optional per-result `date` string (absolute "Jun 5, 2026" or
    relative "2 weeks ago") is passed through RAW; the backend observed-at
    parser handles both and rows without one stay honestly undated.
"""

from __future__ import annotations

import sys
import os
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

import aiohttp

from plugin_interface import ToolPlugin
from lib.search_recency import serper_tbs
from lib.serper_search import (
    SerpNotConfigured,
    SerpSweepFailed,
    dispatch_serper,
    execute_serp_queries,
    new_empty_retry_budget,
    registrable_domain,
)

logger = logging.getLogger(__name__)

PROVIDER_KEY = 'SERP_SEARCH'
DEFAULT_TIMEOUT = 30

# FinOps HARD cap: worst-case metered pages per brand-mention scan. The cohort
# set below is 7 queries; discovery depth is ≤3 pages each and pinpoints are
# 1 page each, so the natural ceiling is 11 (2 discovery × 3 + 5 pinpoint × 1)
# — the cap is a backstop, not the budget. Raised 8→11 with the #1208 target
# expansion: specs execute discovery-first, so a stale cap of 8 would have
# silently truncated 3 of the 5 pinpoints every scan. Growing the target list
# further needs either another documented raise here or a #436-style rotation
# (see darkweb_monitor.py) — never an undocumented unbounded tail.
MAX_SERP_PAGES_PER_MENTION_SCAN = 11

# Review-site pinpoint targets — public consumer/employer-sentiment surfaces a
# bare web query under-ranks. site:-scoped, 1 metered page each (pinpoint tail
# is dry). Consumer: trustpilot/sitejabber/bbb; community: reddit; employer
# reputation: glassdoor. B2B surfaces (g2.com, capterra.com) are deliberately
# NOT defaults — they only pay off for B2B monitors and are gated on
# BrandMonitor.industry in follow-up #1209.
_REVIEW_SITE_TARGETS = (
    'trustpilot.com',
    'reddit.com',
    'glassdoor.com',
    'sitejabber.com',
    'bbb.org',
)


def build_mention_query_cohorts(brand: str) -> List[Dict[str, str]]:
    """The fixed brand-mention cohort set. Quoted brand keeps Google from
    fuzzy-matching unrelated tokens; the write-seam relevance gate
    independently marks brand-absent rows 'unrelated' as defense in depth."""
    b = (brand or '').strip()
    if not b:
        return []
    quoted = f'"{b}"'
    return [
        # Public review / experience chatter — the core sentiment stream.
        {'cohort': 'review', 'query': f'{quoted} review', 'kind': 'discovery'},
        # Complaint / dispute chatter — the negative-tail stream. OR-grouped so
        # one metered query covers the lexicon.
        {'cohort': 'complaint', 'query': f'{quoted} (complaint OR scam OR lawsuit)', 'kind': 'discovery'},
        # Review-site pinpoints — first page only.
        *[
            {'cohort': 'review_site', 'query': f'site:{host} {quoted}', 'kind': 'pinpoint'}
            for host in _REVIEW_SITE_TARGETS
        ],
    ]


def _own_domains(parameters: Dict[str, Any]) -> set:
    """Registrable-domain set of the monitor's own/defensive domains — a
    mention ON the brand's own site is marketing, not public sentiment."""
    out = set()
    dom = parameters.get('domain')
    if isinstance(dom, str) and dom.strip():
        out.add(registrable_domain(dom.strip()))
    owned = parameters.get('ownedDomains')
    if isinstance(owned, list):
        for d in owned:
            if isinstance(d, str) and d.strip():
                out.add(registrable_domain(d.strip()))
    out.discard('')
    return out


def normalize_region(value: Any) -> Optional[str]:
    """#1383 — per-monitor Serper country bias (`gl`). Accepts only a 2-letter
    alpha code (case-insensitive → lowercased). Anything else — None, empty,
    an unresolved `'{{ json searchRegion }}'` template literal, a full country
    name — degrades to None (no `gl`, the pre-#1383 behavior), never an error."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if len(v) == 2 and v.isascii() and v.isalpha():
        return v
    return None


def _to_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


class SerperBrandMentionsTool(ToolPlugin):
    """`serper:brand_mentions` — Google-surface brand mentions for sentiment."""

    @property
    def name(self) -> str:
        return 'serper:brand_mentions'

    @property
    def description(self) -> str:
        return (
            'Collects public brand mentions from Google results (news/blogs/'
            'review + complaint sites) via Serper.dev for the Brand Sentiment '
            'pipeline. Mention COLLECTION only — impersonation/PII threat '
            'hunting stays in brand:monitor_vip_exposure.'
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            'type': 'object',
            'properties': {
                'brand': {
                    'type': 'string',
                    'description': 'Brand keyword the cohorts query on.',
                },
                'domain': {
                    'type': 'string',
                    'description': "Monitor's primary domain (own-site results are skipped).",
                },
                'ownedDomains': {
                    'type': 'array',
                    'items': {'type': 'string'},
                    'description': 'Owned/defensive domains — results on these are skipped.',
                },
                'window_days': {
                    'type': 'integer',
                    'description': (
                        'Recency window in days — mapped to the Google `tbs` '
                        'restriction (trailing `qdr:` bucket, or an absolute '
                        '`cdr:` range when `end_days_ago` is set; omitted = '
                        'all time).'
                    ),
                },
                'end_days_ago': {
                    'type': 'integer',
                    'description': (
                        'Days before now the window ENDS (#1505). >0 slides '
                        'the whole window into the past as an absolute `cdr:` '
                        'date range [now-end-window, now-end]; 0/omitted = '
                        'window ends at now (trailing recency).'
                    ),
                },
                'limit': {
                    'type': 'integer',
                    'description': 'Max items to return (default 40).',
                },
                'region': {
                    'type': 'string',
                    'description': (
                        "Serper country bias (`gl`, ISO-3166 alpha-2, e.g. "
                        "'ca'). Omitted/invalid = no bias (US-default Google)."
                    ),
                },
                'brand_monitor_id': {'type': 'string'},
                'tenantId': {'type': 'string'},
            },
            'required': ['brand'],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            'category': 'social-intelligence',
            'phase': 'discovery',
            'domain': ['drp', 'brand-monitor'],
            'input_type': ['keyword'],
            'output_type': ['mentions'],
            'chainable_after': [],
            'chainable_before': [],
            'taxonomy_domain': ['brand-drp', 'osint'],
            'lifecycle_phase': 'discovery',
            'purpose_count': 'single',
            'primary_purpose': 'public web (Google SERP) brand-mention collection for sentiment',
        }

    def _empty_output(self) -> Dict[str, Any]:
        return {
            'items': [],
            'total': 0,
            'item_kind': 'serp_mention',
            'brand': None,
            '_meta': {'cacheHit': False, 'cacheStale': False},
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        brand = (parameters.get('brand') or '').strip() or None
        if not brand:
            return {
                'success': False, 'error': 'missing_required',
                'missing': ['brand'], 'output': self._empty_output(),
            }

        window_days = _to_int(parameters.get('window_days'))
        if window_days is not None and window_days < 1:
            window_days = None
        # #1505 — optional end anchor (days before now the window ENDS).
        # >0 switches the `tbs` from trailing-recency `qdr:` to an absolute
        # `cdr:` date range so a historical backfill targets a BOUNDED slice.
        # 0/negative/garbage degrades to None == "end at now" (pre-existing).
        end_days_ago = _to_int(parameters.get('end_days_ago'))
        if end_days_ago is not None and end_days_ago < 1:
            end_days_ago = None
        tbs = serper_tbs(window_days, end_days_ago=end_days_ago)

        limit = _to_int(parameters.get('limit'))
        if limit is None or limit < 1:
            limit = 40

        # #1383 — per-monitor country bias; invalid/unset degrades to None.
        region = normalize_region(parameters.get('region'))

        own = _own_domains(parameters)
        specs = build_mention_query_cohorts(brand)

        empty_out = self._empty_output()
        empty_out['brand'] = brand

        async with aiohttp.ClientSession() as session:
            # #1504 — ONE shared retry-on-empty budget for the whole scan so
            # vendor-blink retries are bounded sweep-wide, not per page.
            retry_budget = new_empty_retry_budget()

            async def _serp_dispatch(query: str, page: int) -> Dict[str, Any]:
                return await dispatch_serper(
                    query, page, session,
                    timeout_seconds=DEFAULT_TIMEOUT, tbs=tbs, gl=region,
                    empty_retry_budget=retry_budget,
                )

            try:
                res = await execute_serp_queries(
                    specs,
                    max_pages=MAX_SERP_PAGES_PER_MENTION_SCAN,
                    _dispatch=_serp_dispatch,
                )
            except SerpSweepFailed as exc:
                # Configured-but-broken provider (401/402/429/5xx): FAIL the
                # job — a broken sweep must never read as a clean zero.
                return {
                    'success': False, 'error': str(exc) or 'serp_sweep_failed',
                    'providerKey': PROVIDER_KEY, 'output': empty_out,
                }
            except SerpNotConfigured as exc:
                return {
                    'success': False, 'error': 'no_credentials',
                    'message': str(exc), 'providerKey': PROVIDER_KEY,
                    'output': empty_out,
                }

        status = res.get('status')
        if status == 'unswept_no_provider':
            return {
                'success': False, 'error': 'no_credentials',
                'message': 'No SERP_SEARCH integration configured',
                'providerKey': PROVIDER_KEY, 'output': empty_out,
            }
        if status == 'unswept':
            return {
                'success': False, 'error': 'serp_unswept',
                'providerKey': PROVIDER_KEY, 'output': empty_out,
            }

        seen_urls: set = set()
        items: List[Dict[str, Any]] = []
        skipped_own = 0
        for hit in res.get('results') or []:
            url = hit.get('url')
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            host = urlsplit(url).hostname or ''
            if registrable_domain(host) in own:
                # Own-site result: the brand talking about itself is not
                # public sentiment. Skipped agent-side (cheapest seam).
                skipped_own += 1
                continue
            items.append({
                'url': url,
                'title': hit.get('title') or '',
                'snippet': hit.get('snippet') or '',
                # Raw vendor date string when present; backend parses
                # absolute + relative forms, undated rows stay undated.
                **({'date': hit['date']} if hit.get('date') else {}),
                # #1368 — structured review-rating fields (review-site profile
                # results). Passed through so ingestion can stamp CONFIRMED
                # BrandReviewProfile rows; absent on most organic results.
                **({'rating': hit['rating']} if hit.get('rating') is not None else {}),
                **({'ratingCount': hit['ratingCount']} if hit.get('ratingCount') is not None else {}),
                'cohort': hit.get('_cohort'),
                'query': hit.get('_query'),
                'page': hit.get('_page'),
            })
            if len(items) >= limit:
                break

        out = {
            'items': items,
            'total': len(items),
            'item_kind': 'serp_mention',
            'brand': brand,
            'window_days': window_days,
            'end_days_ago': end_days_ago,
            'tbs': tbs,
            # #1383 — effective country bias ('ca' etc., None = US default);
            # surfaced for scan-log observability.
            'region': region,
            'skipped_own_domain': skipped_own,
            'diagnostics': res.get('diagnostics'),
            '_meta': {'cacheHit': False, 'cacheStale': False},
        }
        return {'success': True, 'output': out}
