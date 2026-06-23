"""ScrapeCreators TikTok Keyword Search Tool — 2026-05-18 remediation.

Restores TikTok keyword discovery that was lost when Phase 5b deleted
`scrapecreators:multi_platform_scan`. Wraps three vendor endpoints under one
ToolPlugin keyed by `mode`:

  mode='keyword'   -> GET /v1/tiktok/search/keyword?query=<q>&cursor=<c>
  mode='hashtag'   -> GET /v1/tiktok/search/hashtag?hashtag=<h>
  mode='users'     -> GET /v1/tiktok/search/users?query=<q>

Output keys are stable and consumed by Phase 5c ingestion
(`processScrapecreatorsTiktokSearchOutput`).

Auth + quota:
  - `checkout_provider('SCRAPECREATORS', requested_units=1)`. SC bills per call.
  - Stub mode disabled at production dispatch (no fabricated data).
  - Cache namespace `ScrapeCreators:tiktok`, TTL 3600s per Phase 5a vendor reqs.
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

_MODE_KEYWORD = 'keyword'
_MODE_HASHTAG = 'hashtag'
_MODE_USERS = 'users'
_VALID_MODES = (_MODE_KEYWORD, _MODE_HASHTAG, _MODE_USERS)


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
    """Normalize a TikTok video. Mirrors SMM `tiktok_post()`.

    TikTok's `search_item_list` wraps each video under `aweme_info` (with
    sibling fields like `type`). The hashtag and `top` endpoints sometimes
    return videos flat. Unwrap defensively.
    """
    if not isinstance(raw, dict):
        return {}
    if isinstance(raw.get('aweme_info'), dict):
        raw = raw['aweme_info']
    elif isinstance(raw.get('item'), dict):
        raw = raw['item']
    stats = raw.get('stats') if isinstance(raw.get('stats'), dict) else (
        raw.get('statistics') if isinstance(raw.get('statistics'), dict) else {}
    )
    author = raw.get('author') if isinstance(raw.get('author'), dict) else {}
    return {
        'post_id': str(_first(raw, 'id', 'aweme_id', 'video_id', 'post_id') or '') or None,
        'url': _first(raw, 'url', 'share_url', 'webVideoUrl'),
        'description': _first(raw, 'desc', 'description', 'text'),
        'created_at': _coerce_iso(_first(raw, 'createTime', 'create_time', 'created_at')),
        'like_count': _first(stats, 'diggCount', 'playCount') if stats else _first(raw, 'like_count', 'digg_count'),
        'comment_count': _first(stats, 'commentCount') if stats else _first(raw, 'comment_count'),
        'play_count': _first(stats, 'playCount') if stats else _first(raw, 'play_count'),
        'share_count': _first(stats, 'shareCount') if stats else _first(raw, 'share_count'),
        'author_handle': _first(author, 'uniqueId', 'unique_id', 'username') if author else _first(raw, 'unique_id', 'username'),
        'author_name': _first(author, 'nickname', 'displayName') if author else _first(raw, 'nickname'),
    }


def _build_user(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a TikTok user record. Mirrors SMM `tiktok_account()`."""
    if not isinstance(raw, dict):
        return {}
    user = raw.get('user') if isinstance(raw.get('user'), dict) else raw
    stats = raw.get('stats') if isinstance(raw.get('stats'), dict) else {}
    return {
        'handle': _first(user, 'uniqueId', 'unique_id', 'username'),
        'display_name': _first(user, 'nickname', 'display_name'),
        'user_id': str(_first(user, 'id', 'sec_uid') or '') or None,
        'bio': _first(user, 'signature', 'bio'),
        'is_verified': bool(_first(user, 'verified', 'is_verified') or False),
        'follower_count': _first(stats, 'followerCount') or _first(user, 'follower_count'),
        'profile_url': (
            f"https://www.tiktok.com/@{_first(user, 'uniqueId', 'unique_id', 'username')}"
            if _first(user, 'uniqueId', 'unique_id', 'username') else None
        ),
        'profile_pic_url': _first(user, 'avatarLarger', 'avatar_url', 'avatarMedium'),
    }


def _extract_list(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Probe known list-bearing keys, then fall back to the first dict-of-dicts
    list at the top level. Covers ScrapeCreators' variable response shapes
    across TikTok endpoints (keyword vs hashtag vs users have different
    wrappers)."""
    if not isinstance(data, dict):
        return []
    # 1. Try known keys — order matches Repo A's `extract_list` probe.
    for key in ('videos', 'aweme_list', 'users', 'user_list', 'posts',
                'results', 'items', 'search_item_list', 'searchResults',
                'search_items', 'hits'):
        v = data.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    # 2. Nested under `data` (some endpoints wrap).
    nested = data.get('data')
    if isinstance(nested, dict):
        for key in ('videos', 'aweme_list', 'users', 'items', 'posts',
                    'searchResults', 'search_item_list'):
            v = nested.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    # 3. Fallback — any top-level value that is a list of dicts.
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


class ScrapeCreatorsTiktokSearchTool(ToolPlugin):
    """`scrapecreators:tiktok_search` — keyword/hashtag/user discovery on TikTok."""

    @property
    def name(self) -> str:
        return 'scrapecreators:tiktok_search'

    @property
    def description(self) -> str:
        return (
            'Keyword-driven TikTok discovery via ScrapeCreators. Modes: '
            '`keyword` searches videos by free-text query (paginated); '
            '`hashtag` searches videos by hashtag (no `#` prefix); '
            '`users` searches accounts by name/handle. Restores discovery '
            'surface lost when the legacy multi_platform_scan tool was '
            'deleted in Phase 5b.'
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            'type': 'object',
            'properties': {
                'mode': {
                    'type': 'string',
                    'enum': list(_VALID_MODES),
                    'default': _MODE_KEYWORD,
                },
                'query': {
                    'type': 'string',
                    'description': 'Free-text query. Required for keyword + users modes.',
                },
                'hashtag': {
                    'type': 'string',
                    'description': (
                        'Hashtag to search (no `#` prefix). Required for hashtag mode.'
                    ),
                },
                'cursor': {
                    'type': 'string',
                    'description': 'Opaque pagination cursor from a prior keyword response.',
                },
                'brand_monitor_id': {'type': 'string'},
                'tenantId': {'type': 'string'},
            },
            'required': [],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            'category': 'social-intelligence',
            'phase': 'discovery',
            'domain': ['drp', 'brand-monitor'],
            'input_type': ['keyword', 'hashtag', 'handle'],
            'output_type': ['posts', 'users'],
            'chainable_after': [],
            'chainable_before': [],
        }

    def _empty_output(self, mode: str) -> Dict[str, Any]:
        return {
            'items': [],
            'total': 0,
            'mode': mode,
            'query': None,
            'hashtag': None,
            'next_cursor': None,
            'has_more': False,
            '_meta': {'cacheHit': False, 'cacheStale': False},
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        mode = str(parameters.get('mode') or _MODE_KEYWORD).lower().strip()
        if mode not in _VALID_MODES:
            return {
                'success': False, 'error': 'invalid_mode',
                'message': f"`mode` must be one of {_VALID_MODES}; got `{mode}`.",
                'output': self._empty_output(mode),
            }

        query = (parameters.get('query') or '').strip() or None
        hashtag_raw = (parameters.get('hashtag') or '').strip() or None
        hashtag = hashtag_raw.lstrip('#') if hashtag_raw else None
        cursor = (parameters.get('cursor') or '').strip() or None

        if mode == _MODE_KEYWORD and not query:
            return {
                'success': False, 'error': 'missing_required',
                'missing': ['query'], 'output': self._empty_output(mode),
            }
        if mode == _MODE_HASHTAG and not hashtag:
            return {
                'success': False, 'error': 'missing_required',
                'missing': ['hashtag'], 'output': self._empty_output(mode),
            }
        if mode == _MODE_USERS and not query:
            return {
                'success': False, 'error': 'missing_required',
                'missing': ['query'], 'output': self._empty_output(mode),
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
        items: List[Dict[str, Any]] = []
        next_cursor: Optional[str] = None
        has_more = False
        sc_credits_remaining: Optional[int] = None
        call_meta: Optional[Dict[str, Any]] = None
        item_kind = 'post'

        try:
            if is_stub:
                logger.error(
                    "[%s] stub API key detected; refusing to synthesize fake "
                    "TikTok search results.", self.name,
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

            if mode == _MODE_KEYWORD:
                path = '/v1/tiktok/search/keyword'
                params: Dict[str, Any] = {'query': query}
                if cursor:
                    params['cursor'] = cursor
                item_kind = 'post'
            elif mode == _MODE_HASHTAG:
                path = '/v1/tiktok/search/hashtag'
                params = {'hashtag': hashtag}
                item_kind = 'post'
            else:  # users
                path = '/v1/tiktok/search/users'
                params = {'query': query}
                item_kind = 'user'

            ns_ttl = ns_ttls.get('tiktok', base_ttl)
            headers = {'x-api-key': api_key}
            timeout = aiohttp.ClientTimeout(total=timeout_seconds + 5)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                resp, call_meta = await upstream_request(
                    session, 'GET', f"{base_url}{path}",
                    headers=headers, params=params,
                    provider_label='scrapecreators',
                    timeout_seconds=timeout_seconds,
                    cache_namespace='tiktok',
                    cache_ttl_seconds=ns_ttl,
                    stale_grace_seconds=stale_grace,
                    tenant_id=tenant_id,
                )
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

            raw_items = _extract_list(data)
            if item_kind == 'user':
                items = [_build_user(it) for it in raw_items]
            else:
                items = [_build_post(it) for it in raw_items]
            items = [it for it in items if it and (it.get('post_id') or it.get('handle'))]
            sc_credits_remaining = _credits_remaining(data)
            nc_raw = data.get('cursor') or data.get('next_cursor') or data.get('max_cursor')
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
            'items': items,
            'item_kind': item_kind,
            'total': len(items),
            'mode': mode,
            'query': query,
            'hashtag': hashtag,
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
                'success': False, 'error': error_code or 'unknown',
                'providerKey': PROVIDER_KEY, 'output': out,
            }
        return {'success': True, 'output': out}
