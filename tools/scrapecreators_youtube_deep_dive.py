"""ScrapeCreators YouTube Deep-Dive Tool — 2026-05-18.

Analyst-driven evidence capture for a known YouTube video URL. Three modes:

  mode='video'        -> GET /v1/youtube/video?url=<url>          (rich video detail)
  mode='transcript'   -> GET /v1/youtube/video/transcript?url=<url>   (~capped at 2 min/segments)
  mode='comments'     -> GET /v1/youtube/video/comments?url=<url>     (top comments)

Output keys are stable and consumed by Phase 5c ingestion
(`processScrapecreatorsKeywordSearchOutput` — same combined handler as the
search tools; recordClass distinguishes shape: youtube_video_detail /
youtube_transcript / youtube_comments).

Auth + quota:
  - `checkout_provider('SCRAPECREATORS', requested_units=1)`. 1 credit/call.
  - Stub mode disabled at production dispatch.
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

_MODE_VIDEO = 'video'
_MODE_TRANSCRIPT = 'transcript'
_MODE_COMMENTS = 'comments'
_VALID_MODES = (_MODE_VIDEO, _MODE_TRANSCRIPT, _MODE_COMMENTS)


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


def _build_video_detail(raw: Dict[str, Any], url: str) -> Dict[str, Any]:
    """Flatten the rich video-detail response."""
    if not isinstance(raw, dict):
        return {}
    # Some SC responses wrap under `video` or `data`.
    if isinstance(raw.get('video'), dict):
        raw = raw['video']
    elif isinstance(raw.get('data'), dict):
        raw = raw['data']
    title = _first(raw, 'title')
    if isinstance(title, dict):
        title = title.get('simpleText') or None
    description = _first(raw, 'description', 'shortDescription')
    return {
        'post_id': str(_first(raw, 'videoId', 'id') or '') or None,
        'url': url,
        'title': str(title) if title else None,
        'description': str(description) if description else None,
        'created_at': _first(raw, 'publishedAt', 'published_at', 'uploadDate'),
        'view_count': _first(raw, 'viewCount', 'view_count'),
        'like_count': _first(raw, 'likeCount', 'like_count'),
        'comment_count': _first(raw, 'commentCount', 'comment_count'),
        'duration': _first(raw, 'duration', 'lengthSeconds'),
        'channel_handle': _first(raw, 'channelHandle', 'ownerHandle'),
        'channel_name': _first(raw, 'channelTitle', 'ownerChannelName', 'channel'),
        'channel_id': _first(raw, 'channelId', 'channel_id'),
        'thumbnail_url': _first(raw, 'thumbnail', 'thumbnail_url'),
        'tags': raw.get('keywords') if isinstance(raw.get('keywords'), list) else None,
    }


def _build_transcript(raw: Dict[str, Any], url: str) -> Dict[str, Any]:
    """Flatten transcript response into a single record with segments."""
    if not isinstance(raw, dict):
        return {}
    segments_raw = (
        raw.get('transcript') if isinstance(raw.get('transcript'), list)
        else raw.get('segments') if isinstance(raw.get('segments'), list)
        else raw.get('items') if isinstance(raw.get('items'), list)
        else []
    )
    segments: List[Dict[str, Any]] = []
    full_text_parts: List[str] = []
    for seg in segments_raw:
        if not isinstance(seg, dict):
            continue
        t = _first(seg, 'text', 'body')
        if not isinstance(t, str):
            continue
        segments.append({
            'start': _first(seg, 'start', 'startMs', 'timestamp'),
            'duration': _first(seg, 'duration', 'durationMs'),
            'text': t,
        })
        full_text_parts.append(t)
    full_text = ' '.join(full_text_parts).strip() or None
    return {
        'post_id': None,  # transcript belongs to a video, not a separate item
        'url': url,
        'segments': segments,
        'segment_count': len(segments),
        'full_text': full_text[:8000] if full_text else None,  # cap
        'language': _first(raw, 'language', 'lang'),
    }


def _build_comment(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    return {
        'comment_id': str(_first(raw, 'commentId', 'comment_id', 'id') or '') or None,
        'author_handle': _first(raw, 'authorHandle', 'author_handle', 'author', 'channelHandle'),
        'text': _first(raw, 'text', 'body', 'content'),
        'score': _first(raw, 'likeCount', 'like_count', 'score'),
        'reply_count': _first(raw, 'replyCount', 'reply_count'),
        'created_at': _first(raw, 'publishedAt', 'published_at', 'created_at'),
        'permalink': _first(raw, 'permalink', 'url'),
    }


class ScrapeCreatorsYoutubeDeepDiveTool(ToolPlugin):
    """`scrapecreators:youtube_deep_dive` — video / transcript / comments
    capture for a flagged YouTube video URL."""

    @property
    def name(self) -> str:
        return 'scrapecreators:youtube_deep_dive'

    @property
    def description(self) -> str:
        return (
            'Analyst-driven evidence capture for a flagged YouTube video. Modes: '
            '`video` (rich detail: title/desc/views/likes/channel/duration), '
            '`transcript` (~2-min auto-caption segments + full text), '
            '`comments` (top comments). Use after a video URL surfaces in '
            'youtube_search or via analyst tip.'
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            'type': 'object',
            'properties': {
                'mode': {
                    'type': 'string',
                    'enum': list(_VALID_MODES),
                    'default': _MODE_VIDEO,
                },
                'url': {
                    'type': 'string',
                    'description': 'YouTube video URL (any standard form).',
                },
                'brand_monitor_id': {'type': 'string'},
                'tenantId': {'type': 'string'},
            },
            'required': ['url'],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            'category': 'social-intelligence',
            'phase': 'evidence-capture',
            'domain': ['drp', 'brand-monitor'],
            'input_type': ['video-url'],
            'output_type': ['video-detail', 'transcript', 'comments'],
            'chainable_after': ['scrapecreators:youtube_search'],
            'chainable_before': [],
        }

    def _empty_output(self, mode: str, url: str) -> Dict[str, Any]:
        kind_map = {
            _MODE_VIDEO: 'video_detail',
            _MODE_TRANSCRIPT: 'transcript',
            _MODE_COMMENTS: 'comments',
        }
        return {
            'items': [],
            'total': 0,
            'mode': mode,
            'url': url,
            'item_kind': kind_map.get(mode, 'post'),
            '_meta': {'cacheHit': False, 'cacheStale': False},
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        mode = str(parameters.get('mode') or _MODE_VIDEO).lower().strip()
        if mode not in _VALID_MODES:
            return {
                'success': False, 'error': 'invalid_mode',
                'message': f"`mode` must be one of {_VALID_MODES}; got `{mode}`.",
                'output': self._empty_output(mode, ''),
            }
        url = (parameters.get('url') or '').strip()
        if not url:
            return {'success': False, 'error': 'missing_required', 'missing': ['url'], 'output': self._empty_output(mode, '')}

        empty_out = self._empty_output(mode, url)

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
        item_kind = (
            'video_detail' if mode == _MODE_VIDEO
            else 'transcript' if mode == _MODE_TRANSCRIPT
            else 'comments'
        )

        try:
            if is_stub:
                logger.error("[%s] stub API key detected; refusing to synthesize fake YouTube deep-dive data.", self.name)
                await reconcile_call(
                    PROVIDER_KEY, lease_token,
                    units=0, success=False, error_code='stub_mode_blocked',
                    cache_hit=None, cache_stale=None,
                )
                return {'success': False, 'error': 'stub_mode_blocked',
                        'message': 'SCRAPECREATORS integration is using a stub API key. Synthetic fixtures are disabled.',
                        'providerKey': PROVIDER_KEY, 'output': empty_out}

            if mode == _MODE_VIDEO:
                path = '/v1/youtube/video'
            elif mode == _MODE_TRANSCRIPT:
                path = '/v1/youtube/video/transcript'
            else:
                path = '/v1/youtube/video/comments'

            ns_ttl = ns_ttls.get('youtube', base_ttl)
            headers = {'x-api-key': api_key}
            timeout = aiohttp.ClientTimeout(total=timeout_seconds + 5)
            params = {'url': url}

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
                    logger.warning("[%s] upstream %s returned %d: %s",
                                   self.name, path, status, body[:200])
                    raise RuntimeError(f"upstream_{status}")
                data = await resp.json()

            if mode == _MODE_VIDEO:
                detail = _build_video_detail(data, url)
                items = [detail] if detail.get('post_id') or detail.get('title') else []
            elif mode == _MODE_TRANSCRIPT:
                transcript = _build_transcript(data, url)
                items = [transcript] if transcript.get('segment_count') else []
            else:  # comments
                raw_comments = (
                    data.get('comments') if isinstance(data.get('comments'), list)
                    else data.get('items') if isinstance(data.get('items'), list)
                    else []
                )
                comments = [_build_comment(c) for c in raw_comments if isinstance(c, dict)]
                comments = [c for c in comments if c and c.get('text')]
                comments.sort(key=lambda c: c.get('score') or 0, reverse=True)
                # Flatten so the ingestion parser (reads top-level post_id/url
                # for nativeId) can ingest each comment — a nested `comment`
                # key has no top-level id/url and would be dropped as "empty".
                items = [{
                    'platform': 'youtube',
                    'post_id': c.get('comment_id'),
                    'url': c.get('permalink') or url,
                    'text': c.get('text'),
                    'score': c.get('score') or 0,
                    **c,
                } for c in comments[:50]]
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
            logger.warning("[%s] upstream call failed (mode=%s): %s", self.name, mode, e)

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
                units=eff_units, success=success, error_code=error_code,
                cache_hit=cache_hit, cache_stale=cache_stale,
            )
        except Exception as rec_err:
            logger.warning("[%s] reconcile failed: %s", self.name, rec_err)

        fetched_at = (call_meta or {}).get('fetched_at')
        out = {
            'items': items,
            'item_kind': item_kind,
            'total': len(items),
            'mode': mode,
            'url': url,
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
