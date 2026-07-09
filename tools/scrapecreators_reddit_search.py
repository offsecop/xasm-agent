"""ScrapeCreators Reddit Keyword Search Tool — 2026-05-18 remediation.

Restores Reddit keyword discovery that was lost when Phase 5b deleted
`scrapecreators:multi_platform_scan`. Wraps THREE vendor endpoints under one
ToolPlugin keyed by `mode`:

  mode='sitewide'    -> GET /v1/reddit/search?query=<q>
  mode='subreddit'   -> GET /v1/reddit/subreddit/search?subreddit=<s>&query=<q>
  mode='listing'     -> GET /v1/reddit/subreddit?name=<s>

Output keys are stable and consumed by Phase 5c ingestion
(`processScrapecreatorsRedditSearchOutput`). Do not rename without
coordinating the backend handler.

Auth + quota (#1143 — bounded pagination):
  - ONE lease per PAGE via `lib/sc_paginated_search.paginated_sc_search`
    (checkout → call → reconcile). SC bills 1 credit per call including error
    responses; cache hits bill 0; a quota cap mid-run parks the sweep and
    returns the pages already collected.
  - Stub mode is DISABLED at the production dispatch path (per the 2026-05-18
    "no fabricated data" directive). If a stub API key is leased, the tool
    refuses with `error: 'stub_mode_blocked'`.

Cache namespace: `ScrapeCreators:reddit` (60min floor per 2026-05-18 TTL
bump). 60-min repeat queries are free.
"""

from __future__ import annotations

import sys
import os
import logging
from typing import Dict, Any, List, Optional

_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

from plugin_interface import ToolPlugin
from lib.wrapper_helpers import first as _first
from lib.search_recency import (
    parse_search_knobs,
    reddit_sort,
    reddit_timeframe,
)
from lib.sc_paginated_search import paginated_sc_search

logger = logging.getLogger(__name__)

PROVIDER_KEY = 'SCRAPECREATORS'
BASE_URL = 'https://api.scrapecreators.com'
DEFAULT_TIMEOUT = 30
STUB_API_KEY = 'sk-dev-stub-scrapecreators'

CACHE_NAMESPACE = 'ScrapeCreators:reddit'
DEFAULT_NAMESPACE_TTL = 3600

_MODE_SITEWIDE = 'sitewide'
_MODE_SUBREDDIT = 'subreddit'
_MODE_LISTING = 'listing'
_VALID_MODES = (_MODE_SITEWIDE, _MODE_SUBREDDIT, _MODE_LISTING)


def _build_permalink(raw: Dict[str, Any]) -> str:
    perma = _first(raw, 'permalink', 'url')
    if isinstance(perma, str) and perma:
        if perma.startswith('http'):
            return perma
        if perma.startswith('/'):
            return f'https://www.reddit.com{perma}'
    return ''


def _coerce_iso(ts: Any) -> Optional[str]:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        try:
            from datetime import datetime, timezone
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace('+00:00', 'Z')
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(ts, str):
        return ts
    return None


def _build_post(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a Reddit post record. Mirrors SMM `reddit_post()`."""
    if not isinstance(raw, dict):
        return {}
    return {
        'post_id': str(_first(raw, 'id', 'name', 'post_id') or '') or None,
        'subreddit': _first(raw, 'subreddit', 'subreddit_name_prefixed'),
        'author_handle': _first(raw, 'author', 'author_handle'),
        'title': _first(raw, 'title'),
        'selftext': _first(raw, 'selftext', 'text', 'body'),
        'score': _first(raw, 'score', 'ups'),
        'num_comments': _first(raw, 'num_comments', 'comment_count'),
        'permalink': _build_permalink(raw),
        'created_at': _coerce_iso(_first(raw, 'created_utc', 'created_at', 'created')),
        'flair': _first(raw, 'link_flair_text', 'flair'),
        'over_18': bool(_first(raw, 'over_18') or False),
    }


def _extract_list(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Probe known list-bearing keys, then fall back to first list-of-dicts."""
    if not isinstance(data, dict):
        return []
    for key in ('posts', 'results', 'items', 'hits', 'search_items',
                'searchResults', 'subreddits'):
        v = data.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    nested = data.get('data')
    if isinstance(nested, dict):
        for key in ('posts', 'results', 'items', 'children', 'searchResults'):
            v = nested.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    for v in data.values():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            return [x for x in v if isinstance(x, dict)]
    return []


def _credits_remaining(data: Dict[str, Any]) -> Optional[int]:
    if not isinstance(data, dict):
        return None
    rem = data.get('credits_remaining')
    if rem is None:
        return None
    try:
        return int(rem)
    except (TypeError, ValueError):
        return None


class ScrapeCreatorsRedditSearchTool(ToolPlugin):
    """`scrapecreators:reddit_search` — keyword discovery across Reddit."""

    @property
    def name(self) -> str:
        return 'scrapecreators:reddit_search'

    @property
    def description(self) -> str:
        return (
            'Keyword-driven Reddit discovery via ScrapeCreators. Three modes: '
            '`sitewide` searches all of Reddit by query; `subreddit` searches a '
            'specific subreddit by query; `listing` returns the most recent posts '
            'in a subreddit without keyword filtering. Restores discovery surface '
            'lost when the legacy multi_platform_scan tool was deleted in Phase 5b.'
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            'type': 'object',
            'properties': {
                'mode': {
                    'type': 'string',
                    'enum': list(_VALID_MODES),
                    'default': _MODE_SITEWIDE,
                    'description': (
                        'sitewide = global Reddit keyword search; '
                        'subreddit = sub-scoped keyword search (requires both subreddit and query); '
                        'listing = recent posts in a subreddit (requires subreddit only).'
                    ),
                },
                'query': {
                    'type': 'string',
                    'description': 'Keyword to search. Required for sitewide + subreddit modes.',
                },
                'subreddit': {
                    'type': 'string',
                    'description': (
                        'Subreddit name without the `r/` prefix. Required for '
                        'subreddit + listing modes.'
                    ),
                },
                'cursor': {
                    'type': 'string',
                    'description': (
                        'Opaque pagination cursor from a prior response (the '
                        "vendor's `after` post id). Seeds the pagination loop."
                    ),
                },
                # #1143 — semantic recency/pagination knobs (mapped to the
                # vendor's real params: sort/timeframe/after). Defensive:
                # missing/garbage values degrade to single-page vendor defaults.
                'limit': {
                    'type': 'integer',
                    'description': 'Max posts to accumulate across pages (default 50, cap 200).',
                },
                'sort': {
                    'type': 'string',
                    'enum': ['new', 'relevance', 'top'],
                    'description': 'Result ordering (vendor `sort`; omit = vendor default relevance).',
                },
                'window_days': {
                    'type': 'integer',
                    'description': (
                        'Recency window in days — bucketed to the vendor '
                        '`timeframe` enum (day/week/month/year/all).'
                    ),
                },
                'max_pages': {
                    'type': 'integer',
                    'description': (
                        'Bounded pagination depth for sitewide search (default 1, '
                        'hard cap 5). Each page is one billed vendor call.'
                    ),
                },
                'brand_monitor_id': {
                    'type': 'string',
                    'description': 'Backend BrandMonitor id to attribute findings to.',
                },
                'tenantId': {
                    'type': 'string',
                    'description': 'Tenant scope for ingestion attribution.',
                },
            },
            'required': [],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            'category': 'social-intelligence',
            'phase': 'discovery',
            'domain': ['drp', 'brand-monitor'],
            'input_type': ['keyword', 'subreddit-name'],
            'output_type': ['posts'],
            'chainable_after': [],
            'chainable_before': ['scrapecreators:reddit_thread_enrichment'],
            # --- canonical taxonomy (#559) ---
            'taxonomy_domain': ['brand-drp', 'osint'],
            'lifecycle_phase': 'discovery',
            'purpose_count': 'multi',
            'primary_purpose': 'brand/DRP Reddit discovery via keyword and subreddit search',
            'secondary_purposes': [
                {'mode': 'sitewide', 'purpose': 'keyword search across all of Reddit'},
                {'mode': 'subreddit', 'purpose': 'keyword search within a specific subreddit'},
                {'mode': 'listing', 'purpose': 'latest posts in a subreddit (no keyword filter)'},
            ],
        }

    def _empty_output(self, mode: str) -> Dict[str, Any]:
        return {
            'items': [],
            'total': 0,
            'mode': mode,
            'query': None,
            'subreddit': None,
            'next_cursor': None,
            'has_more': False,
            '_meta': {'cacheHit': False, 'cacheStale': False},
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        mode = str(parameters.get('mode') or _MODE_SITEWIDE).lower().strip()
        if mode not in _VALID_MODES:
            return {
                'success': False,
                'error': 'invalid_mode',
                'message': f"`mode` must be one of {_VALID_MODES}; got `{mode}`.",
                'output': self._empty_output(mode),
            }

        query = (parameters.get('query') or '').strip() or None
        subreddit_raw = (parameters.get('subreddit') or '').strip() or None
        if isinstance(subreddit_raw, str) and subreddit_raw:
            # strip 'r/' or '/r/' prefix if analyst pasted it
            subreddit = subreddit_raw.lstrip('/').removeprefix('r/').strip() or None
        else:
            subreddit = None
        cursor = (parameters.get('cursor') or '').strip() or None

        # Conditional required-field checks (per CLAUDE.md BUG-563/564 — schema
        # declares the union, execute() enforces the per-mode shape).
        if mode == _MODE_SITEWIDE and not query:
            return {
                'success': False,
                'error': 'missing_required',
                'missing': ['query'],
                'output': self._empty_output(mode),
            }
        if mode == _MODE_SUBREDDIT and not (query and subreddit):
            return {
                'success': False,
                'error': 'missing_required',
                'missing': [k for k in ('query', 'subreddit')
                            if not (query if k == 'query' else subreddit)],
                'output': self._empty_output(mode),
            }
        if mode == _MODE_LISTING and not subreddit:
            return {
                'success': False,
                'error': 'missing_required',
                'missing': ['subreddit'],
                'output': self._empty_output(mode),
            }

        empty_out = self._empty_output(mode)

        # #1143 — semantic recency/pagination knobs (defensive parsing; garbage
        # degrades to the pre-#1143 single-page vendor-default behavior).
        knobs = parse_search_knobs(parameters)
        limit = knobs['limit']
        # Pagination is verified for the SITEWIDE endpoint only (`after`
        # cursor); subreddit/listing stay single-call.
        max_pages = knobs['max_pages'] if mode == _MODE_SITEWIDE else 1
        sort = reddit_sort(knobs['sort']) if mode != _MODE_LISTING else None
        timeframe = (
            reddit_timeframe(knobs['window_days'])
            if mode != _MODE_LISTING
            else None
        )

        # Build the per-mode endpoint + base params. Vendor param names
        # verified 2026-07: sitewide pagination is `after` (the old `cursor`
        # param was silently ignored upstream — pagination never advanced).
        if mode == _MODE_SITEWIDE:
            path = '/v1/reddit/search'
            base_params: Dict[str, Any] = {'query': query}
            if sort:
                base_params['sort'] = sort
            if timeframe:
                base_params['timeframe'] = timeframe
            cursor_param: Optional[str] = 'after'
        elif mode == _MODE_SUBREDDIT:
            path = '/v1/reddit/subreddit/search'
            base_params = {'subreddit': subreddit, 'query': query}
            if sort:
                base_params['sort'] = sort
            if timeframe:
                base_params['timeframe'] = timeframe
            cursor_param = None  # pagination unverified for this endpoint
            if cursor:
                base_params['after'] = cursor
        else:  # listing
            path = '/v1/reddit/subreddit'
            base_params = {'name': subreddit}
            cursor_param = None

        def _items(data: Dict[str, Any]) -> List[Dict[str, Any]]:
            return [p for p in (_build_post(rp) for rp in _extract_list(data)) if p]

        res = await paginated_sc_search(
            tool_name=self.name,
            path=path,
            base_params=base_params,
            cache_namespace='reddit',
            extract_items=_items,
            cursor_param=cursor_param,
            initial_cursor=cursor if cursor_param else None,
            max_pages=max_pages,
            limit=limit,
            logger=logger,
        )

        if res['kind'] == 'quota_exceeded':
            return {
                'success': False, 'error': 'quota_exceeded',
                'retryAfter': res.get('retry_after'), 'providerKey': PROVIDER_KEY,
                'output': empty_out,
            }
        if res['kind'] == 'no_credentials':
            return {
                'success': False, 'error': 'no_credentials',
                'message': res.get('message'), 'providerKey': PROVIDER_KEY,
                'output': empty_out,
            }
        if res['kind'] == 'stub_mode_blocked':
            return {
                'success': False, 'error': 'stub_mode_blocked',
                'message': res.get('message'), 'providerKey': PROVIDER_KEY,
                'output': empty_out,
            }
        if res['kind'] == 'checkout_returned_empty':
            return {
                'success': False, 'error': 'checkout_returned_empty',
                'output': empty_out,
            }

        posts = res['items']
        out = {
            'items': posts,
            'total': len(posts),
            'mode': mode,
            'query': query,
            'subreddit': subreddit,
            'next_cursor': res['next_cursor'],
            'has_more': res['has_more'],
            'sc_credits_remaining': res['credits_remaining'],
            '_meta': res['meta'],
        }
        if res['kind'] != 'ok':
            return {
                'success': False,
                'error': res.get('error_code') or 'unknown',
                'providerKey': PROVIDER_KEY,
                'output': out,
            }
        return {'success': True, 'output': out}
