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

Auth + quota:
  - `checkout_provider('SCRAPECREATORS', requested_units=1)` — SC bills 1
    credit per call. Reconcile units=0 on cache hit, units=1 on miss.
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

import aiohttp

from plugin_interface import ToolPlugin
from lib.integration_credentials import (
    checkout_provider,
    reconcile_call,
    upstream_request,
    QuotaExceededError,
    IntegrationCredentialsError,
)
from lib.wrapper_helpers import first as _first

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
                    'description': 'Opaque pagination cursor from a prior response.',
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

        try:
            lease = await checkout_provider(PROVIDER_KEY, requested_units=1)
        except QuotaExceededError as qe:
            return {
                'success': False, 'error': 'quota_exceeded',
                'retryAfter': qe.retry_after, 'providerKey': PROVIDER_KEY,
                'output': empty_out,
            }
        except IntegrationCredentialsError as ce:
            logger.error("[%s] credentials error: %s", self.name, ce)
            return {
                'success': False, 'error': 'no_credentials',
                'message': str(ce), 'providerKey': PROVIDER_KEY,
                'output': empty_out,
            }

        api_key = lease.get('apiKey')
        lease_token = lease.get('leaseToken')
        if not api_key or not lease_token:
            return {
                'success': False, 'error': 'checkout_returned_empty',
                'output': empty_out,
            }

        base_url = lease.get('baseUrl') or BASE_URL
        timeout_seconds = lease.get('timeoutSeconds') or DEFAULT_TIMEOUT
        is_stub = api_key == STUB_API_KEY
        tenant_id = lease.get('tenantId')
        stale_grace = lease.get('staleGraceSeconds')
        ns_ttls = lease.get('cacheNamespaceTtls') or {}
        base_ttl = lease.get('cacheTtlSeconds')

        success = False
        error_code: Optional[str] = None
        posts: List[Dict[str, Any]] = []
        next_cursor: Optional[str] = None
        has_more = False
        sc_credits_remaining: Optional[int] = None
        call_meta: Optional[Dict[str, Any]] = None

        try:
            if is_stub:
                logger.error(
                    "[%s] stub API key detected; refusing to synthesize fake "
                    "Reddit search results.", self.name,
                )
                await reconcile_call(
                    PROVIDER_KEY, lease_token,
                    units=0, success=False,
                    error_code='stub_mode_blocked',
                    cache_hit=None, cache_stale=None,
                )
                return {
                    'success': False, 'error': 'stub_mode_blocked',
                    'message': (
                        'SCRAPECREATORS integration is using a stub API key. '
                        'Synthetic fixtures are disabled. Provision a real key.'
                    ),
                    'providerKey': PROVIDER_KEY,
                    'output': empty_out,
                }

            # Build the per-mode endpoint + params.
            if mode == _MODE_SITEWIDE:
                path = '/v1/reddit/search'
                params: Dict[str, Any] = {'query': query}
                if cursor:
                    params['cursor'] = cursor
            elif mode == _MODE_SUBREDDIT:
                path = '/v1/reddit/subreddit/search'
                params = {'subreddit': subreddit, 'query': query}
                if cursor:
                    params['cursor'] = cursor
            else:  # listing
                path = '/v1/reddit/subreddit'
                params = {'name': subreddit}

            ns_ttl = ns_ttls.get('reddit', base_ttl)
            headers = {'x-api-key': api_key}
            timeout = aiohttp.ClientTimeout(total=timeout_seconds + 5)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                resp, call_meta = await upstream_request(
                    session, 'GET', f"{base_url}{path}",
                    headers=headers, params=params,
                    provider_label='scrapecreators',
                    timeout_seconds=timeout_seconds,
                    cache_namespace='reddit',
                    cache_ttl_seconds=ns_ttl,
                    stale_grace_seconds=stale_grace,
                    tenant_id=tenant_id,
                )
                # `upstream_request` returns a real aiohttp response on miss or
                # a CachedResponse on hit. Both expose `status` and `json()`.
                status = getattr(resp, 'status', 0)
                if status == 429:
                    raise QuotaExceededError(
                        provider_key=PROVIDER_KEY, retry_after=5,
                        period_resets_at=None, cap=None, current_usage=None,
                    )
                if status >= 400:
                    body = await resp.text() if hasattr(resp, 'text') else ''
                    error_code = f'http_{status}'
                    logger.warning(
                        "[%s] upstream %s returned %d: %s",
                        self.name, path, status, body[:200],
                    )
                    raise RuntimeError(f"upstream_{status}")

                data = await resp.json()

            raw_posts = _extract_list(data)
            posts = [_build_post(p) for p in raw_posts]
            posts = [p for p in posts if p]
            sc_credits_remaining = _credits_remaining(data)
            nc_raw = data.get('cursor') or data.get('next_cursor') or data.get('after')
            next_cursor = str(nc_raw) if nc_raw else None
            has_more = bool(data.get('has_more')) or bool(next_cursor)

            success = True
        except QuotaExceededError as qe:
            error_code = 'quota_exceeded'
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=0, success=False, error_code=error_code,
                cache_hit=None, cache_stale=None,
            )
            return {
                'success': False, 'error': error_code,
                'retryAfter': qe.retry_after, 'providerKey': PROVIDER_KEY,
                'output': empty_out,
            }
        except Exception as e:
            error_code = type(e).__name__
            logger.warning(
                "[%s] upstream call failed (mode=%s): %s",
                self.name, mode, e,
            )

        # Reconcile (always runs; cache-hit -> units=0).
        cache_hit = bool(call_meta and call_meta.get('cache_hit'))
        cache_stale = bool(call_meta and call_meta.get('cache_stale'))
        # ScrapeCreators bills per call INCLUDING error responses, so bill a
        # unit whenever the call actually fired (call_meta set, not a cache hit)
        # — not only on success. Under-billing failed-but-fired calls drifts the
        # per-tenant quota ledger below real provider usage (provider-ban risk).
        call_fired = call_meta is not None and not cache_hit
        eff_units = 0 if cache_hit else (1 if call_fired else 0)
        try:
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=eff_units, success=success,
                error_code=error_code,
                cache_hit=cache_hit, cache_stale=cache_stale,
            )
        except Exception as rec_err:
            logger.warning(
                "[%s] reconcile failed: %s", self.name, rec_err,
            )

        fetched_at = (call_meta or {}).get('fetched_at')
        out = {
            'items': posts,
            'total': len(posts),
            'mode': mode,
            'query': query,
            'subreddit': subreddit,
            'next_cursor': next_cursor,
            'has_more': has_more,
            'sc_credits_remaining': sc_credits_remaining,
            '_meta': {
                'cacheHit': cache_hit,
                'cacheStale': cache_stale,
                **({'fetchedAt': fetched_at} if fetched_at else {}),
            },
        }
        if not success:
            return {
                'success': False,
                'error': error_code or 'unknown',
                'providerKey': PROVIDER_KEY,
                'output': out,
            }
        return {'success': True, 'output': out}
