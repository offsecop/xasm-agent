"""ScrapeCreators Threads (Meta's X-clone) Keyword Search Tool — 2026-05-18 remediation.

Restores Threads keyword discovery that was lost when Phase 5b deleted
`scrapecreators:multi_platform_scan`. Wraps two vendor endpoints:

  mode='posts'   -> GET /v1/threads/search?query=<q>
  mode='users'   -> GET /v1/threads/search/users?query=<q>

Output keys are stable and consumed by Phase 5c ingestion
(`processScrapecreatorsThreadsSearchOutput`).

Auth + quota (#1143 — shared single-call fetch):
  - ONE lease per call via `lib/sc_paginated_search.paginated_sc_search`
    (the Threads search endpoint does NOT paginate — it returns at most 10
    results per call; `window_days` maps to its start_date/end_date range).
  - Stub mode disabled at production dispatch.
  - Cache namespace `ScrapeCreators:threads`, TTL 3600s per Phase 5a vendor reqs.
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
from lib.search_recency import parse_search_knobs, threads_date_range
from lib.sc_paginated_search import paginated_sc_search

logger = logging.getLogger(__name__)

PROVIDER_KEY = 'SCRAPECREATORS'
BASE_URL = 'https://api.scrapecreators.com'
DEFAULT_TIMEOUT = 30
STUB_API_KEY = 'sk-dev-stub-scrapecreators'

_MODE_POSTS = 'posts'
_MODE_USERS = 'users'
_VALID_MODES = (_MODE_POSTS, _MODE_USERS)


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
    """Normalize a Threads post. Mirrors SMM `threads_post()`."""
    if not isinstance(raw, dict):
        return {}
    raw_caption = raw.get('caption')
    caption: Dict[str, Any] = raw_caption if isinstance(raw_caption, dict) else {}
    raw_user = raw.get('user')
    user: Dict[str, Any] = raw_user if isinstance(raw_user, dict) else {}
    text = caption.get('text') or _first(raw, 'text', 'body')
    return {
        'post_id': str(_first(raw, 'pk', 'id', 'post_id') or '') or None,
        'code': _first(raw, 'code', 'short_code'),
        'url': (
            f"https://www.threads.net/@{user.get('username') or _first(raw, 'username')}/post/{_first(raw, 'code', 'short_code')}"
            if (user.get('username') or _first(raw, 'username')) and _first(raw, 'code', 'short_code')
            else _first(raw, 'permalink', 'url')
        ),
        'text': text,
        'created_at': _coerce_iso(_first(raw, 'taken_at', 'created_at')),
        'like_count': _first(raw, 'like_count', 'likes'),
        'reply_count': _first(raw, 'reply_count', 'comment_count'),
        'author_handle': _first(user, 'username') if user else _first(raw, 'username', 'author_handle'),
        'author_name': _first(user, 'full_name', 'name') if user else _first(raw, 'full_name'),
    }


def _build_user(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a Threads user record. Mirrors SMM `threads_account()`."""
    if not isinstance(raw, dict):
        return {}
    raw_user = raw.get('user')
    user: Dict[str, Any] = raw_user if isinstance(raw_user, dict) else raw
    handle = _first(user, 'username', 'handle')
    return {
        'handle': handle,
        'display_name': _first(user, 'full_name', 'display_name', 'name'),
        'user_id': str(_first(user, 'pk', 'id', 'user_id') or '') or None,
        'bio': _first(user, 'biography', 'bio'),
        'is_verified': bool(_first(user, 'is_verified', 'verified') or False),
        'follower_count': _first(user, 'follower_count', 'followers'),
        'profile_url': f"https://www.threads.net/@{handle}" if handle else None,
        'profile_pic_url': _first(user, 'profile_pic_url', 'avatar_url'),
    }


def _extract_list(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    for key in ('posts', 'threads', 'users', 'results', 'items', 'data', 'search_items'):
        v = data.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    nested = data.get('data')
    if isinstance(nested, dict):
        for key in ('posts', 'threads', 'users'):
            v = nested.get(key)
            if isinstance(v, list):
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


class ScrapeCreatorsThreadsSearchTool(ToolPlugin):
    """`scrapecreators:threads_search` — keyword discovery on Meta's Threads."""

    @property
    def name(self) -> str:
        return 'scrapecreators:threads_search'

    @property
    def description(self) -> str:
        return (
            'Keyword-driven Threads (Meta) discovery via ScrapeCreators. Modes: '
            '`posts` searches threads by free-text query; `users` searches '
            'accounts by name/handle. Restores discovery surface lost when the '
            'legacy multi_platform_scan tool was deleted in Phase 5b.'
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            'type': 'object',
            'properties': {
                'mode': {
                    'type': 'string',
                    'enum': list(_VALID_MODES),
                    'default': _MODE_POSTS,
                },
                'query': {
                    'type': 'string',
                    'description': 'Free-text query. Required for both modes.',
                },
                # #1143 — recency knob. The Threads search endpoint supports
                # ONLY start_date/end_date (computed agent-side from
                # window_days) — no sort, no pagination (≤10 results/call).
                'limit': {
                    'type': 'integer',
                    'description': 'Max items to return (vendor caps a call at ~10 anyway).',
                },
                'window_days': {
                    'type': 'integer',
                    'description': 'Recency window in days — mapped to the vendor start_date/end_date range.',
                },
                'end_days_ago': {
                    'type': 'integer',
                    'description': (
                        'Optional end anchor: the window ENDS this many days in '
                        'the past (0/omitted = now). Lets a historical backfill '
                        'target a bounded past slice.'
                    ),
                },
                'brand_monitor_id': {'type': 'string'},
                'tenantId': {'type': 'string'},
            },
            'required': ['query'],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            'category': 'social-intelligence',
            'phase': 'discovery',
            'domain': ['drp', 'brand-monitor'],
            'input_type': ['keyword'],
            'output_type': ['posts', 'users'],
            'chainable_after': [],
            'chainable_before': [],
            # --- canonical taxonomy (#559) ---
            'taxonomy_domain': ['brand-drp', 'osint'],
            'lifecycle_phase': 'discovery',
            'purpose_count': 'multi',
            'primary_purpose': 'brand/DRP Threads discovery via post and user search',
            'secondary_purposes': [
                {'mode': 'posts', 'purpose': 'keyword search across Threads posts'},
                {'mode': 'users', 'purpose': 'keyword search across Threads user accounts'},
            ],
        }

    def _empty_output(self, mode: str) -> Dict[str, Any]:
        return {
            'items': [],
            'total': 0,
            'mode': mode,
            'query': None,
            'item_kind': 'post' if mode == _MODE_POSTS else 'user',
            '_meta': {'cacheHit': False, 'cacheStale': False},
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        mode = str(parameters.get('mode') or _MODE_POSTS).lower().strip()
        if mode not in _VALID_MODES:
            return {
                'success': False, 'error': 'invalid_mode',
                'message': f"`mode` must be one of {_VALID_MODES}; got `{mode}`.",
                'output': self._empty_output(mode),
            }

        query = (parameters.get('query') or '').strip() or None
        if not query:
            return {
                'success': False, 'error': 'missing_required',
                'missing': ['query'], 'output': self._empty_output(mode),
            }

        empty_out = self._empty_output(mode)
        item_kind = 'post' if mode == _MODE_POSTS else 'user'

        # #1143 — recency knob (defensive; garbage degrades to no date filter).
        knobs = parse_search_knobs(parameters)
        limit = knobs['limit']

        if mode == _MODE_POSTS:
            path = '/v1/threads/search'
            base_params: Dict[str, Any] = {'query': query}
            # The ONLY time-ranged SC keyword endpoint: absolute YYYY-MM-DD
            # dates computed agent-side (step templates can't carry them).
            # `end_days_ago` slides the whole window into the past for a
            # historical backfill. Provider cap: the endpoint returns at most
            # ~10 un-paginated results per call regardless of range width —
            # this bounds recency, it does NOT raise volume.
            start_date, end_date = threads_date_range(
                knobs['window_days'],
                end_days_ago=knobs['end_days_ago'],
            )
            if start_date and end_date:
                base_params['start_date'] = start_date
                base_params['end_date'] = end_date
        else:
            path = '/v1/threads/search/users'
            base_params = {'query': query}

        def _items(data: Dict[str, Any]) -> List[Dict[str, Any]]:
            raw_items = _extract_list(data)
            if item_kind == 'user':
                built = [_build_user(it) for it in raw_items]
                return [it for it in built if it and it.get('handle')]
            built = [_build_post(it) for it in raw_items]
            return [it for it in built if it and (it.get('post_id') or it.get('text'))]

        res = await paginated_sc_search(
            tool_name=self.name,
            path=path,
            base_params=base_params,
            cache_namespace='threads',
            extract_items=_items,
            cursor_param=None,  # the endpoint does not paginate
            max_pages=1,
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
            'sc_credits_remaining': res['credits_remaining'],
            '_meta': res['meta'],
        }
        if res['kind'] != 'ok':
            return {
                'success': False, 'error': res.get('error_code') or 'unknown',
                'providerKey': PROVIDER_KEY, 'output': out,
            }
        return {'success': True, 'output': out}
