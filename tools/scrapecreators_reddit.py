"""ScrapeCreators Reddit Thread Enrichment Tool — DRP P0+P1 migration Phase 5b.

Implements `scrapecreators:reddit_thread_enrichment`. Given the URL of a
flagged Reddit post, pulls the comments via SC `/v1/reddit/post/comments`
and returns the top-N by score. Phase 4 SMM playbook §7.2 measured this
endpoint at ~44× signal density per credit — the dominant narrative,
brand response, and customer-impact correlates surface in the top-10 score
band without analyst review of the full thread.

Output keys are stable and consumed by Phase 5c ingestion — do not rename
without coordinating with the backend handler.

Auth + quota:
  - `checkout_provider('SCRAPECREATORS', requested_units=1)` — bills per call.
  - Stub mode (apiKey == STUB_API_KEY) synthesizes a deterministic top-10
    thread (`_synthetic: true` on every record) and reconciles `units=0`.

Endpoint: GET /v1/reddit/post/comments?url=<url>
Cache namespace: 'ScrapeCreators:reddit_comments' (matches Phase 5a
`drp-vendor-requirements.ts` key `reddit_comments`).
"""

from __future__ import annotations

import sys
import os
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

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

CACHE_NAMESPACE = 'ScrapeCreators:reddit_comments'
DEFAULT_NAMESPACE_TTL = 300  # SMM playbook §7 — short TTL, threads update fast.


def _build_permalink(raw: Dict[str, Any]) -> str:
    perma = _first(raw, 'permalink')
    if isinstance(perma, str) and perma:
        if perma.startswith('http'):
            return perma
        if perma.startswith('/'):
            return f'https://www.reddit.com{perma}'
    return ''


def _coerce_iso(ts: Any) -> Optional[str]:
    """Reddit returns `created_utc` as a unix-epoch float. Normalize to ISO8601."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        try:
            return (
                datetime.fromtimestamp(float(ts), tz=timezone.utc)
                .isoformat()
                .replace('+00:00', 'Z')
            )
        except (OSError, ValueError, OverflowError):
            return None
    if isinstance(ts, str):
        return ts
    return None


def _build_comment(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one SC reddit comment dict into the shape Phase 5c ingestion
    consumes. Mirrors SMM `app/scrapecreators/models.py:reddit_comment()`."""
    score = _first(raw, 'score', 'ups')
    return {
        'comment_id': str(_first(raw, 'id', 'name') or ''),
        'author_handle': _first(raw, 'author') or '',
        'text': str(_first(raw, 'body', 'text') or ''),
        'score': int(score) if isinstance(score, (int, float)) else None,
        'created_at': _coerce_iso(_first(raw, 'created_utc', 'created_at')),
        'permalink': _build_permalink(raw),
    }


class ScrapeCreatorsRedditThreadEnrichmentTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "scrapecreators:reddit_thread_enrichment"

    @property
    def description(self) -> str:
        return (
            "Pull the top-N comments (by score) for a flagged Reddit thread "
            "via ScrapeCreators `/v1/reddit/post/comments`. Phase 4 playbook "
            "§7.2 measured ~44× signal density per credit on this endpoint."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full Reddit comment-thread URL.",
                },
                "top_n": {
                    "type": "integer",
                    "description": "Number of top-scored comments to return (default 10, max 50).",
                    "default": 10,
                },
                "brand_monitor_id": {
                    "type": "string",
                    "description": "BrandMonitor id this enrichment belongs to (forwarded to ingestion).",
                },
                "tenantId": {
                    "type": "string",
                    "description": "Tenant id (forwarded to ingestion). The agent's lease is already tenant-scoped.",
                },
            },
            "required": ["url"],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "drp_enrichment",
            "phase": 6,
            "domain": ["brand_protection", "social"],
            "input_type": ["url"],
            "output_type": ["reddit_comments"],
            "chainable_after": [],
            "chainable_before": ["drp:scoring"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        url = (parameters.get('url') or '').strip()
        top_n = int(parameters.get('top_n', 10) or 10)
        top_n = max(1, min(top_n, 50))

        empty_out: Dict[str, Any] = {
            "items": [], "total": 0, "url": url, "subreddit": None,
            "thread_id": None, "thread_title": None, "thread_score": None,
            "total_comment_count": None, "top_n": top_n,
        }

        if not url:
            return {"success": False, "error": "url_required", "output": empty_out}

        try:
            lease = await checkout_provider(PROVIDER_KEY, requested_units=1)
        except QuotaExceededError as e:
            logger.warning(f"[SC:reddit_thread] Quota exceeded: {e}")
            return {
                "success": False, "error": "quota_exceeded",
                "retryAfter": e.retry_after, "providerKey": PROVIDER_KEY,
                "output": empty_out,
            }
        except IntegrationCredentialsError as e:
            logger.error(f"[SC:reddit_thread] No backend lease: {e}")
            return {
                "success": False, "error": "no_credentials",
                "message": (
                    "No backend integration configured for SCRAPECREATORS."
                ),
                "output": empty_out,
            }

        api_key = lease.get('apiKey')
        lease_token = lease.get('leaseToken')
        if not api_key or not lease_token:
            return {
                "success": False, "error": "checkout_returned_empty",
                "output": empty_out,
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
        thread_meta: Dict[str, Any] = {}
        call_meta: Optional[Dict[str, Any]] = None

        try:
            if is_stub:
                # 2026-05-18 — stub-mode synthesis disabled at production
                # dispatch. Fail loud rather than fabricate Reddit thread
                # data.
                logger.error(
                    "[%s] stub API key detected; refusing to synthesize "
                    "fake Reddit thread enrichment.", self.name,
                )
                await reconcile_call(
                    PROVIDER_KEY, lease_token,
                    units=0, success=False,
                    error_code='stub_mode_blocked',
                    cache_hit=None, cache_stale=None,
                )
                return {
                    'success': False,
                    'error': 'stub_mode_blocked',
                    'message': (
                        'SCRAPECREATORS integration is using a stub API key. '
                        'Synthetic fixtures are disabled. Provision a real key.'
                    ),
                    'providerKey': PROVIDER_KEY,
                    'output': empty_out,
                }
            items, thread_meta, call_meta = await self._query(
                api_key, url, top_n,
                base_url=base_url, timeout_seconds=timeout_seconds,
                tenant_id=tenant_id, base_ttl=base_ttl,
                ns_ttls=ns_ttls, stale_grace=stale_grace,
            )
            success = True
        except Exception as e:
            error_code = type(e).__name__
            logger.warning(f"[SC:reddit_thread] Upstream call failed: {e}")
        finally:
            if is_stub:
                eff_units: int = 0
                rec_cache_hit: Optional[bool] = None
                rec_cache_stale: Optional[bool] = None
            elif (
                call_meta is not None
                and call_meta.get('cache_hit')
                and not call_meta.get('cache_stale')
            ):
                eff_units = 0
                rec_cache_hit = True
                rec_cache_stale = False
            else:
                eff_units = 1
                rec_cache_hit = False
                rec_cache_stale = (
                    bool(call_meta and call_meta.get('cache_stale')) or None
                )
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=eff_units, success=success, error_code=error_code,
                cache_hit=rec_cache_hit, cache_stale=rec_cache_stale,
            )

        meta_out: Dict[str, Any] = {
            'cacheHit': bool(call_meta and call_meta.get('cache_hit')),
            'cacheStale': bool(call_meta and call_meta.get('cache_stale')),
        }
        if call_meta and call_meta.get('fetched_at'):
            meta_out['fetchedAt'] = (
                datetime.fromtimestamp(call_meta['fetched_at'], tz=timezone.utc)
                .isoformat()
                .replace('+00:00', 'Z')
            )

        return {
            "success": success,
            "output": {
                "items": items,
                "total": len(items),
                "url": url,
                "subreddit": thread_meta.get('subreddit'),
                "thread_id": thread_meta.get('thread_id'),
                "thread_title": thread_meta.get('thread_title'),
                "thread_score": thread_meta.get('thread_score'),
                "total_comment_count": thread_meta.get('total_comment_count'),
                # 2026-05-18 — thread-level post fields now captured.
                "post_text": thread_meta.get('post_text'),
                "author_handle": thread_meta.get('author_handle'),
                "created_at": thread_meta.get('created_at'),
                "flair": thread_meta.get('flair'),
                "over_18": thread_meta.get('over_18'),
                "top_n": top_n,
                "_meta": meta_out,
            },
            **({"error": error_code} if not success and error_code else {}),
        }

    async def _query(
        self, api_key: str, url: str, top_n: int,
        *, base_url: str, timeout_seconds: float,
        tenant_id: Optional[str], base_ttl: Optional[int],
        ns_ttls: Dict[str, int], stale_grace: Optional[int],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
        headers = {'x-api-key': api_key, 'accept': 'application/json'}
        endpoint = f"{base_url}/v1/reddit/post/comments"
        params = {'url': url}

        ttl = ns_ttls.get(CACHE_NAMESPACE) or base_ttl or DEFAULT_NAMESPACE_TTL
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            resp, meta = await upstream_request(
                session, 'GET', endpoint,
                headers=headers, params=params,
                provider_label='ScrapeCreators:reddit_comments',
                timeout_seconds=timeout_seconds,
                cache_namespace=CACHE_NAMESPACE,
                cache_ttl_seconds=ttl,
                stale_grace_seconds=stale_grace,
                tenant_id=tenant_id,
            )
            try:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(
                        f"SC reddit_thread HTTP {resp.status}: {text[:200]}"
                    )
                data = await resp.json()
            finally:
                await resp.release()

        if not isinstance(data, dict):
            data = {}

        raw_comments = data.get('comments')
        if not isinstance(raw_comments, list):
            # Fallback: SC may sometimes flatten the envelope.
            raw_comments = (
                data.get('items') or data.get('results') or []
            )

        all_comments = [
            _build_comment(c) for c in raw_comments
            if isinstance(c, dict)
        ]
        all_comments.sort(key=lambda c: c.get('score') or 0, reverse=True)
        top = all_comments[:top_n]

        items = [
            {
                'platform': 'reddit',
                'comment': c,
                'score': c.get('score') or 0,
            }
            for c in top
        ]

        # Thread-level fields — SC's /v1/reddit/post/comments DOES return a
        # `post` block alongside `comments` (verified live 2026-05-18). Pull
        # the rich post-body fields so the FE can render thread context, not
        # just comments.
        thread = data.get('post') if isinstance(data.get('post'), dict) else data
        def _t(*keys):
            for k in keys:
                if isinstance(thread, dict) and thread.get(k) not in (None, ''):
                    return thread.get(k)
            return None
        score_raw = _t('score', 'ups')
        nc_raw = _t('num_comments', 'comment_count')
        created_raw = _t('created_utc', 'created', 'created_at')
        if isinstance(created_raw, (int, float)):
            try:
                created_iso = datetime.fromtimestamp(
                    float(created_raw), tz=timezone.utc,
                ).isoformat().replace('+00:00', 'Z')
            except (OverflowError, OSError, ValueError):
                created_iso = None
        elif isinstance(created_raw, str):
            created_iso = created_raw
        else:
            created_iso = None
        thread_meta = {
            'subreddit': _t('subreddit', 'subreddit_name'),
            'thread_id': str(_t('id', 'name')) if _t('id', 'name') is not None else None,
            'thread_title': _t('title'),
            'thread_score': int(score_raw) if isinstance(score_raw, (int, float)) else None,
            'total_comment_count': (
                int(nc_raw) if isinstance(nc_raw, (int, float))
                else (len(all_comments) or None)
            ),
            'post_text': _t('selftext', 'body', 'text'),
            'author_handle': _t('author'),
            'created_at': created_iso,
            'flair': _t('link_flair_text', 'flair'),
            'over_18': bool(_t('over_18') or False),
        }
        return items, thread_meta, meta
