"""ScrapeCreators TikTok Keyword Search Tool — 2026-05-18 remediation.

Restores TikTok keyword discovery that was lost when Phase 5b deleted
`scrapecreators:multi_platform_scan`. Wraps three vendor endpoints under one
ToolPlugin keyed by `mode`:

  mode='keyword'   -> GET /v1/tiktok/search/keyword?query=<q>&cursor=<c>
  mode='hashtag'   -> GET /v1/tiktok/search/hashtag?hashtag=<h>
  mode='users'     -> GET /v1/tiktok/search/users?query=<q>

Output keys are stable and consumed by Phase 5c ingestion
(`processScrapecreatorsTiktokSearchOutput`).

Auth + quota (#1143 — bounded pagination):
  - ONE lease per PAGE via `lib/sc_paginated_search.paginated_sc_search`
    (checkout → call → reconcile); SC bills per call including errors; cache
    hits bill 0; a quota cap mid-run parks the sweep with partial results.
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

from plugin_interface import ToolPlugin
from lib.search_recency import (
    parse_search_knobs,
    tiktok_date_posted,
    tiktok_sort_by,
)
from lib.sc_paginated_search import paginated_sc_search
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
                # #1143 — semantic recency/pagination knobs (mapped to the
                # vendor's real params: sort_by / date_posted / cursor).
                'limit': {
                    'type': 'integer',
                    'description': 'Max items to accumulate across pages (default 50, cap 200).',
                },
                'sort': {
                    'type': 'string',
                    'enum': ['new', 'relevance', 'top'],
                    'description': "Result ordering (mapped to vendor `sort_by`: new→date-posted, top→most-liked).",
                },
                'window_days': {
                    'type': 'integer',
                    'description': 'Recency window in days — bucketed to the vendor `date_posted` enum.',
                },
                'max_pages': {
                    'type': 'integer',
                    'description': 'Bounded pagination depth for keyword search (default 1, hard cap 5). Each page is one billed vendor call.',
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
            # --- canonical taxonomy (#559) ---
            'taxonomy_domain': ['brand-drp', 'osint'],
            'lifecycle_phase': 'discovery',
            'purpose_count': 'multi',
            'primary_purpose': 'brand/DRP TikTok discovery via keyword, hashtag and user search',
            'secondary_purposes': [
                {'mode': 'keyword', 'purpose': 'keyword video search'},
                {'mode': 'hashtag', 'purpose': 'hashtag video search'},
                {'mode': 'users', 'purpose': 'user-account search'},
            ],
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

        # #1143 — semantic recency/pagination knobs (defensive; garbage
        # degrades to the pre-#1143 single-page vendor-default behavior).
        knobs = parse_search_knobs(parameters)
        limit = knobs['limit']
        # Pagination is verified for the KEYWORD endpoint only; hashtag/users
        # stay single-call.
        max_pages = knobs['max_pages'] if mode == _MODE_KEYWORD else 1

        if mode == _MODE_KEYWORD:
            path = '/v1/tiktok/search/keyword'
            base_params: Dict[str, Any] = {'query': query}
            sort_by = tiktok_sort_by(knobs['sort'])
            if sort_by:
                base_params['sort_by'] = sort_by
            date_posted = tiktok_date_posted(knobs['window_days'])
            if date_posted:
                base_params['date_posted'] = date_posted
            cursor_param: Optional[str] = 'cursor'
            item_kind = 'post'
        elif mode == _MODE_HASHTAG:
            path = '/v1/tiktok/search/hashtag'
            base_params = {'hashtag': hashtag}
            cursor_param = None
            item_kind = 'post'
        else:  # users
            path = '/v1/tiktok/search/users'
            base_params = {'query': query}
            cursor_param = None
            item_kind = 'user'

        def _items(data: Dict[str, Any]) -> List[Dict[str, Any]]:
            raw_items = _extract_list(data)
            if item_kind == 'user':
                built = [_build_user(it) for it in raw_items]
            else:
                built = [_build_post(it) for it in raw_items]
            return [it for it in built
                    if it and (it.get('post_id') or it.get('handle'))]

        def _cursor(data: Dict[str, Any]) -> Optional[str]:
            nc = data.get('cursor') or data.get('next_cursor') or data.get('max_cursor')
            return str(nc) if nc else None

        res = await paginated_sc_search(
            tool_name=self.name,
            path=path,
            base_params=base_params,
            cache_namespace='tiktok',
            extract_items=_items,
            cursor_param=cursor_param,
            initial_cursor=cursor if cursor_param else None,
            extract_cursor=_cursor,
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

        items = res['items']
        out = {
            'items': items,
            'item_kind': item_kind,
            'total': len(items),
            'mode': mode,
            'query': query,
            'hashtag': hashtag,
            'next_cursor': res['next_cursor'],
            'has_more': res['has_more'],
            'sc_credits_remaining': res['credits_remaining'],
            '_meta': res['meta'],
        }
        if res['kind'] != 'ok':
            return {
                'success': False, 'error': res.get('error_code') or 'unknown',
                'providerKey': PROVIDER_KEY, 'output': out,
            }
        return {'success': True, 'output': out}
