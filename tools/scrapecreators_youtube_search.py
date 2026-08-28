"""ScrapeCreators YouTube Keyword Search Tool — 2026-05-18 remediation.

Wires the three SC YouTube discovery endpoints under one ToolPlugin:

  mode='keyword'  -> GET /v1/youtube/search?query=<q>       (mixed: videos+channels+lives)
  mode='hashtag'  -> GET /v1/youtube/search/hashtag?hashtag=<h>
  mode='channel'  -> GET /v1/youtube/channel?handle=<@h>    (channel anchor lookup)

Output keys are stable and consumed by Phase 5c ingestion
(`processScrapecreatorsKeywordSearchOutput`). Same combined handler as
reddit/tiktok/threads; recordClass discriminates the platform + kind:
youtube_post / youtube_channel / youtube_hashtag_post.

Auth + quota (#1143 — bounded pagination):
  - ONE lease per PAGE via `lib/sc_paginated_search.paginated_sc_search`
    (checkout → call → reconcile); 1 credit per fired call including errors;
    cache hits bill 0; a quota cap mid-run parks the sweep with partial results.
  - Stub mode disabled at production dispatch (no fabricated data).
  - Cache namespace `ScrapeCreators:youtube`, TTL 3600s.
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
from lib.search_recency import parse_search_knobs, youtube_upload_date
from lib.sc_paginated_search import paginated_sc_search

logger = logging.getLogger(__name__)

PROVIDER_KEY = 'SCRAPECREATORS'
BASE_URL = 'https://api.scrapecreators.com'
DEFAULT_TIMEOUT = 30
STUB_API_KEY = 'sk-dev-stub-scrapecreators'

_MODE_KEYWORD = 'keyword'
_MODE_HASHTAG = 'hashtag'
_MODE_CHANNEL = 'channel'
_VALID_MODES = (_MODE_KEYWORD, _MODE_HASHTAG, _MODE_CHANNEL)


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


def _build_video(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a YouTube video record. Mirrors SMM `youtube_post()`.

    SC's `/v1/youtube/search` returns mixed types (video / channel / live);
    the wrapper has a `type` field and the actual record nested under
    `videoRenderer`, `channelRenderer`, or `liveBroadcastRenderer`.
    """
    if not isinstance(raw, dict):
        return {}
    # Unwrap renderer shapes when present.
    for k in ('videoRenderer', 'liveBroadcastRenderer', 'video', 'item'):
        v = raw.get(k)
        if isinstance(v, dict):
            raw = v
            break
    title = _first(raw, 'title')
    if isinstance(title, dict):
        # Some YT shapes wrap as {runs:[{text}]} or {simpleText}
        title = title.get('simpleText') or (
            ''.join(r.get('text', '') for r in title.get('runs', []) if isinstance(r, dict))
        ) or None
    description = _first(raw, 'description', 'descriptionSnippet')
    if isinstance(description, dict):
        description = description.get('simpleText') or (
            ''.join(r.get('text', '') for r in description.get('runs', []) if isinstance(r, dict))
        ) or None
    video_id = str(_first(raw, 'videoId', 'video_id', 'id') or '') or None
    url = _first(raw, 'url', 'shareUrl', 'webUrl')
    if not url and video_id:
        url = f'https://www.youtube.com/watch?v={video_id}'
    return {
        'post_id': video_id,
        'url': url,
        'title': str(title) if title else None,
        'description': str(description) if description else None,
        'created_at': _coerce_iso(_first(raw, 'publishedTimeText', 'publishedTime', 'published_at')),
        'view_count': _first(raw, 'viewCount', 'view_count', 'viewCountText'),
        'duration': _first(raw, 'lengthText', 'duration', 'durationSeconds'),
        'thumbnail_url': _first(raw, 'thumbnail', 'thumbnail_url'),
        'channel_handle': _first(raw, 'ownerHandle', 'channelHandle', 'channel_handle'),
        'channel_name': _first(raw, 'ownerText', 'channelTitle', 'channelName', 'channel'),
        'channel_id': _first(raw, 'channelId', 'channel_id'),
    }


def _build_channel(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a YouTube channel record. Mirrors SMM `youtube_account()`."""
    if not isinstance(raw, dict):
        return {}
    for k in ('channelRenderer', 'channel', 'item'):
        v = raw.get(k)
        if isinstance(v, dict):
            raw = v
            break
    handle = _first(raw, 'handle', 'channelHandle', 'customUrl')
    if isinstance(handle, str) and not handle.startswith('@'):
        handle = f'@{handle}'
    channel_id = str(_first(raw, 'channelId', 'id') or '') or None
    title = _first(raw, 'title', 'channelTitle', 'name')
    if isinstance(title, dict):
        title = title.get('simpleText') or None
    url = _first(raw, 'url', 'channelUrl')
    if not url and handle:
        url = f'https://www.youtube.com/{handle}'
    return {
        'handle': handle,
        'display_name': str(title) if title else None,
        'user_id': channel_id,
        'bio': _first(raw, 'description', 'descriptionSnippet'),
        'is_verified': bool(_first(raw, 'isVerified', 'verified') or False),
        'follower_count': _first(raw, 'subscriberCount', 'subscriberCountText', 'followers'),
        'profile_url': url,
        'profile_pic_url': _first(raw, 'thumbnail', 'avatarUrl', 'profile_pic_url'),
    }


def _extract_list(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """SC YouTube response variants — probe known list-bearing keys, then
    fall back to first list-of-dicts at top level."""
    if not isinstance(data, dict):
        return []
    for key in ('videos', 'results', 'items', 'channels', 'lives',
                'searchResults', 'search_items', 'hits'):
        v = data.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    nested = data.get('data')
    if isinstance(nested, dict):
        for key in ('videos', 'results', 'items', 'channels'):
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


class ScrapeCreatorsYoutubeSearchTool(ToolPlugin):
    """`scrapecreators:youtube_search` — keyword/hashtag/channel discovery on YouTube."""

    @property
    def name(self) -> str:
        return 'scrapecreators:youtube_search'

    @property
    def description(self) -> str:
        return (
            'Keyword-driven YouTube discovery via ScrapeCreators. Modes: '
            '`keyword` searches videos+channels+lives by query; `hashtag` '
            'searches by hashtag (no `#` prefix); `channel` performs an '
            'anchor lookup on a single channel handle (e.g. `@channelhandle`).'
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
                    'description': 'Free-text query. Required for keyword mode.',
                },
                'hashtag': {
                    'type': 'string',
                    'description': 'Hashtag (no `#`). Required for hashtag mode.',
                },
                'handle': {
                    'type': 'string',
                    'description': 'Channel handle, with or without `@`. Required for channel mode.',
                },
                # #1143 — semantic recency/pagination knobs (mapped to the
                # vendor's real params: uploadDate / continuationToken; the
                # vendor sortBy has NO recency value so `sort` is not mapped).
                'limit': {
                    'type': 'integer',
                    'description': 'Max items to accumulate across pages (default 50, cap 200).',
                },
                'window_days': {
                    'type': 'integer',
                    'description': 'Recency window in days — bucketed to the vendor `uploadDate` enum.',
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
            'output_type': ['videos', 'channels'],
            'chainable_after': [],
            'chainable_before': ['scrapecreators:youtube_deep_dive'],
            # --- canonical taxonomy (#559) ---
            'taxonomy_domain': ['brand-drp', 'osint'],
            'lifecycle_phase': 'discovery',
            'purpose_count': 'multi',
            'primary_purpose': 'brand/DRP YouTube discovery via keyword, hashtag and channel lookup',
            'secondary_purposes': [
                {'mode': 'keyword', 'purpose': 'keyword search (videos + channels + lives)'},
                {'mode': 'hashtag', 'purpose': 'hashtag video search'},
                {'mode': 'channel', 'purpose': 'channel anchor lookup by handle'},
            ],
        }

    def _empty_output(self, mode: str) -> Dict[str, Any]:
        return {
            'items': [],
            'total': 0,
            'mode': mode,
            'query': None,
            'hashtag': None,
            'handle': None,
            'item_kind': 'user' if mode == _MODE_CHANNEL else 'post',
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
        handle_raw = (parameters.get('handle') or '').strip() or None
        handle = handle_raw if handle_raw else None
        if handle and not handle.startswith('@'):
            handle = f'@{handle}'

        if mode == _MODE_KEYWORD and not query:
            return {'success': False, 'error': 'missing_required', 'missing': ['query'], 'output': self._empty_output(mode)}
        if mode == _MODE_HASHTAG and not hashtag:
            return {'success': False, 'error': 'missing_required', 'missing': ['hashtag'], 'output': self._empty_output(mode)}
        if mode == _MODE_CHANNEL and not handle:
            return {'success': False, 'error': 'missing_required', 'missing': ['handle'], 'output': self._empty_output(mode)}

        empty_out = self._empty_output(mode)

        # #1143 — semantic recency/pagination knobs (defensive; garbage
        # degrades to the pre-#1143 single-page vendor-default behavior).
        knobs = parse_search_knobs(parameters)
        limit = knobs['limit']
        # Pagination is verified for the KEYWORD endpoint only
        # (continuationToken); hashtag/channel stay single-call.
        max_pages = knobs['max_pages'] if mode == _MODE_KEYWORD else 1
        item_kind = 'user' if mode == _MODE_CHANNEL else 'post'

        if mode == _MODE_KEYWORD:
            path = '/v1/youtube/search'
            base_params: Dict[str, Any] = {'query': query}
            upload_date = youtube_upload_date(knobs['window_days'])
            if upload_date:
                base_params['uploadDate'] = upload_date
            cursor_param: Optional[str] = 'continuationToken'
        elif mode == _MODE_HASHTAG:
            path = '/v1/youtube/search/hashtag'
            base_params = {'hashtag': hashtag}
            cursor_param = None
        else:  # channel
            path = '/v1/youtube/channel'
            base_params = {'handle': handle}
            cursor_param = None

        def _items(data: Dict[str, Any]) -> List[Dict[str, Any]]:
            if mode == _MODE_CHANNEL:
                # Channel anchor lookup returns a single channel record (not a list).
                if isinstance(data, dict):
                    channel = _build_channel(data)
                    if channel.get('handle') or channel.get('user_id'):
                        return [channel]
                return []
            raw_items = _extract_list(data)
            if mode == _MODE_HASHTAG:
                built = [_build_video(it) for it in raw_items]
                return [it for it in built if it and (it.get('post_id') or it.get('url'))]
            # keyword — mixed; classify by hint fields
            built: List[Dict[str, Any]] = []
            for it in raw_items:
                # If the item exposes channelId AND no videoId → channel
                cid = it.get('channelId') or (
                    it.get('channelRenderer', {}).get('channelId')
                    if isinstance(it.get('channelRenderer'), dict) else None
                )
                vid = it.get('videoId') or (
                    it.get('videoRenderer', {}).get('videoId')
                    if isinstance(it.get('videoRenderer'), dict) else None
                )
                if vid:
                    built.append(_build_video(it))
                elif cid and not vid:
                    ch = _build_channel(it)
                    # Inject a synthetic post_id-like field for dedup parity.
                    ch['post_id'] = cid
                    built.append(ch)
                else:
                    built.append(_build_video(it))
            return [it for it in built if it and (it.get('post_id') or it.get('url') or it.get('handle'))]

        def _cursor(data: Dict[str, Any]) -> Optional[str]:
            nc = data.get('continuationToken') or data.get('next_cursor') or data.get('cursor')
            return str(nc) if nc else None

        res = await paginated_sc_search(
            tool_name=self.name,
            path=path,
            base_params=base_params,
            cache_namespace='youtube',
            extract_items=_items,
            cursor_param=cursor_param,
            extract_cursor=_cursor,
            max_pages=max_pages,
            limit=limit,
            logger=logger,
        )

        if res['kind'] == 'quota_exceeded':
            return {'success': False, 'error': 'quota_exceeded', 'retryAfter': res.get('retry_after'), 'providerKey': PROVIDER_KEY, 'output': empty_out}
        if res['kind'] == 'no_credentials':
            return {'success': False, 'error': 'no_credentials', 'message': res.get('message'), 'providerKey': PROVIDER_KEY, 'output': empty_out}
        if res['kind'] == 'stub_mode_blocked':
            return {'success': False, 'error': 'stub_mode_blocked', 'message': res.get('message'), 'providerKey': PROVIDER_KEY, 'output': empty_out}
        if res['kind'] == 'checkout_returned_empty':
            return {'success': False, 'error': 'checkout_returned_empty', 'output': empty_out}

        items = res['items']
        out = {
            'items': items,
            'item_kind': item_kind,
            'total': len(items),
            'mode': mode,
            'query': query,
            'hashtag': hashtag,
            'handle': handle,
            'sc_credits_remaining': res['credits_remaining'],
            '_meta': res['meta'],
        }
        if res['kind'] != 'ok':
            return {'success': False, 'error': res.get('error_code') or 'unknown', 'providerKey': PROVIDER_KEY, 'output': out}
        return {'success': True, 'output': out}
