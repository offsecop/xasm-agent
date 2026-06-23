"""ScrapeCreators YouTube Keyword Search Tool — 2026-05-18 remediation.

Wires the three SC YouTube discovery endpoints under one ToolPlugin:

  mode='keyword'  -> GET /v1/youtube/search?query=<q>       (mixed: videos+channels+lives)
  mode='hashtag'  -> GET /v1/youtube/search/hashtag?hashtag=<h>
  mode='channel'  -> GET /v1/youtube/channel?handle=<@h>    (channel anchor lookup)

Output keys are stable and consumed by Phase 5c ingestion
(`processScrapecreatorsKeywordSearchOutput`). Same combined handler as
reddit/tiktok/threads; recordClass discriminates the platform + kind:
youtube_post / youtube_channel / youtube_hashtag_post.

Auth + quota:
  - `checkout_provider('SCRAPECREATORS', requested_units=1)`. 1 credit/call.
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
            'anchor lookup on a single channel handle (e.g. `@Questrade`).'
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

        try:
            lease = await checkout_provider(PROVIDER_KEY, requested_units=1)
        except QuotaExceededError as qe:
            return {'success': False, 'error': 'quota_exceeded', 'retryAfter': qe.retry_after, 'providerKey': PROVIDER_KEY, 'output': empty_out}
        except IntegrationCredentialsError as ce:
            logger.error("[%s] credentials error: %s", self.name, ce)
            return {'success': False, 'error': 'no_credentials', 'message': str(ce), 'providerKey': PROVIDER_KEY, 'output': empty_out}

        api_key = lease.get('apiKey')
        lease_token = lease.get('leaseToken')
        if not api_key or not lease_token:
            return {'success': False, 'error': 'checkout_returned_empty', 'output': empty_out}

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
        sc_credits_remaining: Optional[int] = None
        call_meta: Optional[Dict[str, Any]] = None
        item_kind = 'user' if mode == _MODE_CHANNEL else 'post'

        try:
            if is_stub:
                logger.error(
                    "[%s] stub API key detected; refusing to synthesize fake YouTube results.",
                    self.name,
                )
                await reconcile_call(
                    PROVIDER_KEY, lease_token,
                    units=0, success=False, error_code='stub_mode_blocked',
                    cache_hit=None, cache_stale=None,
                )
                return {'success': False, 'error': 'stub_mode_blocked',
                        'message': 'SCRAPECREATORS integration is using a stub API key. Synthetic fixtures are disabled. Provision a real key.',
                        'providerKey': PROVIDER_KEY, 'output': empty_out}

            if mode == _MODE_KEYWORD:
                path = '/v1/youtube/search'
                params: Dict[str, Any] = {'query': query}
            elif mode == _MODE_HASHTAG:
                path = '/v1/youtube/search/hashtag'
                params = {'hashtag': hashtag}
            else:  # channel
                path = '/v1/youtube/channel'
                params = {'handle': handle}

            ns_ttl = ns_ttls.get('youtube', base_ttl)
            headers = {'x-api-key': api_key}
            timeout = aiohttp.ClientTimeout(total=timeout_seconds + 5)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                resp, call_meta = await upstream_request(
                    session, 'GET', f"{base_url}{path}",
                    headers=headers, params=params,
                    provider_label='scrapecreators',
                    timeout_seconds=timeout_seconds,
                    cache_namespace='youtube',
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

            if mode == _MODE_CHANNEL:
                # Channel anchor lookup returns a single channel record (not a list).
                if isinstance(data, dict):
                    channel = _build_channel(data)
                    items = [channel] if channel.get('handle') or channel.get('user_id') else []
            else:
                raw_items = _extract_list(data)
                if mode == _MODE_HASHTAG:
                    items = [_build_video(it) for it in raw_items]
                    items = [it for it in items if it and (it.get('post_id') or it.get('url'))]
                else:  # keyword — mixed; classify by hint fields
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
                    items = [it for it in built if it and (it.get('post_id') or it.get('url') or it.get('handle'))]
            sc_credits_remaining = _credits_remaining(data)

            success = True
        except QuotaExceededError as qe:
            error_code = 'quota_exceeded'
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=0, success=False, error_code=error_code,
                cache_hit=None, cache_stale=None,
            )
            return {'success': False, 'error': error_code, 'retryAfter': qe.retry_after, 'providerKey': PROVIDER_KEY, 'output': empty_out}
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
            'handle': handle,
            'sc_credits_remaining': sc_credits_remaining,
            '_meta': {
                'cacheHit': cache_hit,
                'cacheStale': cache_stale,
                **({'fetchedAt': fetched_at} if fetched_at else {}),
            },
        }
        if not success:
            return {'success': False, 'error': error_code or 'unknown', 'providerKey': PROVIDER_KEY, 'output': out}
        return {'success': True, 'output': out}
