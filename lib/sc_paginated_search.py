"""#1143 — shared bounded-pagination fetch loop for the ScrapeCreators
keyword-search tools (reddit / tiktok / threads / youtube).

One quota lease per page (checkout → upstream call → reconcile), so:
  - the per-tenant ledger bills exactly the pages that FIRED (ScrapeCreators
    bills error responses too; cache hits bill 0);
  - a quota cap hit mid-run PARKS the sweep — pages already collected are
    returned as a partial success — instead of error-storming;
  - a mis-templated `max_pages` can never exceed `search_recency.MAX_PAGES_CAP`
    (the caller clamps via `parse_search_knobs`).

The four tools keep their own schemas, param mapping (see search_recency.py)
and output contracts; this module owns ONLY the loop + quota discipline so the
four copies cannot drift.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

import aiohttp

from lib.integration_credentials import (
    checkout_provider,
    reconcile_call,
    upstream_request,
    QuotaExceededError,
    IntegrationCredentialsError,
)

DEFAULT_TIMEOUT = 30
STUB_API_KEY = 'sk-dev-stub-scrapecreators'
BASE_URL = 'https://api.scrapecreators.com'
PROVIDER_KEY = 'SCRAPECREATORS'


def _default_extract_cursor(data: Dict[str, Any]) -> Optional[str]:
    nc = data.get('cursor') or data.get('next_cursor') or data.get('after')
    return str(nc) if nc else None


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


async def paginated_sc_search(
    *,
    tool_name: str,
    path: str,
    base_params: Dict[str, Any],
    cache_namespace: str,
    extract_items: Callable[[Dict[str, Any]], List[Dict[str, Any]]],
    cursor_param: Optional[str] = None,
    initial_cursor: Optional[str] = None,
    extract_cursor: Callable[[Dict[str, Any]], Optional[str]] = _default_extract_cursor,
    max_pages: int = 1,
    limit: int = 50,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """Run a bounded, quota-disciplined page loop against one SC endpoint.

    Returns a dict with:
      kind: 'ok' | 'quota_exceeded' | 'no_credentials' |
            'checkout_returned_empty' | 'stub_mode_blocked' | 'error'
      items, next_cursor, has_more, credits_remaining, meta (dict),
      error_code, retry_after, message

    kind == 'ok' may still be PARTIAL (meta.quotaBlocked / meta.pageError) —
    pages collected before the interruption are preserved. A page-1 failure
    maps to the matching terminal kind so callers keep their original
    single-call error contracts.
    """
    log = logger or logging.getLogger(tool_name)
    if cursor_param is None:
        max_pages = 1  # endpoint cannot paginate

    items: List[Dict[str, Any]] = []
    next_cursor: Optional[str] = initial_cursor
    has_more = False
    credits_remaining: Optional[int] = None
    pages_fired = 0
    pages_cached = 0
    quota_blocked = False
    cache_stale_any = False
    last_fetched_at: Optional[str] = None
    ok = False
    error_code: Optional[str] = None
    page_error_note: Optional[str] = None

    for page_idx in range(max_pages):
        # ── per-page quota lease ────────────────────────────────────────────
        try:
            lease = await checkout_provider(PROVIDER_KEY, requested_units=1)
        except QuotaExceededError as qe:
            if page_idx == 0:
                return {
                    'kind': 'quota_exceeded',
                    'retry_after': qe.retry_after,
                    'items': [], 'next_cursor': None, 'has_more': False,
                    'credits_remaining': None, 'meta': {},
                    'error_code': 'quota_exceeded', 'message': None,
                }
            quota_blocked = True
            break
        except IntegrationCredentialsError as ce:
            log.error("[%s] credentials error: %s", tool_name, ce)
            if page_idx == 0:
                return {
                    'kind': 'no_credentials', 'message': str(ce),
                    'items': [], 'next_cursor': None, 'has_more': False,
                    'credits_remaining': None, 'meta': {},
                    'error_code': 'no_credentials', 'retry_after': None,
                }
            break

        api_key = lease.get('apiKey')
        lease_token = lease.get('leaseToken')
        if not api_key or not lease_token:
            if page_idx == 0:
                return {
                    'kind': 'checkout_returned_empty',
                    'items': [], 'next_cursor': None, 'has_more': False,
                    'credits_remaining': None, 'meta': {},
                    'error_code': 'checkout_returned_empty',
                    'retry_after': None, 'message': None,
                }
            break

        if api_key == STUB_API_KEY:
            log.error(
                "[%s] stub API key detected; refusing to synthesize fake "
                "search results.", tool_name,
            )
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=0, success=False, error_code='stub_mode_blocked',
                cache_hit=None, cache_stale=None,
            )
            return {
                'kind': 'stub_mode_blocked',
                'message': (
                    'SCRAPECREATORS integration is using a stub API key. '
                    'Synthetic fixtures are disabled. Provision a real key.'
                ),
                'items': [], 'next_cursor': None, 'has_more': False,
                'credits_remaining': None, 'meta': {},
                'error_code': 'stub_mode_blocked', 'retry_after': None,
            }

        base_url = lease.get('baseUrl') or BASE_URL
        timeout_seconds = lease.get('timeoutSeconds') or DEFAULT_TIMEOUT
        tenant_id = lease.get('tenantId')
        stale_grace = lease.get('staleGraceSeconds')
        ns_ttls = lease.get('cacheNamespaceTtls') or {}
        ns_ttl = ns_ttls.get(cache_namespace, lease.get('cacheTtlSeconds'))

        params = dict(base_params)
        if cursor_param and next_cursor:
            params[cursor_param] = next_cursor

        page_ok = False
        page_error: Optional[str] = None
        page_quota_429 = False
        call_meta: Optional[Dict[str, Any]] = None
        data: Optional[Dict[str, Any]] = None

        try:
            headers = {'x-api-key': api_key}
            timeout = aiohttp.ClientTimeout(total=timeout_seconds + 5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                resp, call_meta = await upstream_request(
                    session, 'GET', f"{base_url}{path}",
                    headers=headers, params=params,
                    provider_label='scrapecreators',
                    timeout_seconds=timeout_seconds,
                    cache_namespace=cache_namespace,
                    cache_ttl_seconds=ns_ttl,
                    stale_grace_seconds=stale_grace,
                    tenant_id=tenant_id,
                )
                # Real aiohttp response on miss, CachedResponse on hit — both
                # expose `status` and `json()`.
                status = getattr(resp, 'status', 0)
                if status == 429:
                    page_quota_429 = True
                    raise RuntimeError('upstream_429')
                if status >= 400:
                    body = await resp.text() if hasattr(resp, 'text') else ''
                    page_error = f'http_{status}'
                    log.warning(
                        "[%s] upstream %s returned %d: %s",
                        tool_name, path, status, body[:200],
                    )
                    raise RuntimeError(f"upstream_{status}")
                data = await resp.json()
            page_ok = True
        except Exception as e:
            if page_error is None and not page_quota_429:
                page_error = type(e).__name__
            if not page_quota_429:
                log.warning(
                    "[%s] upstream call failed (page %d): %s",
                    tool_name, page_idx + 1, e,
                )

        # ── per-page reconcile: fired pages bill 1 (even on error — SC bills
        # error responses); cache hits and never-fired 429s bill 0. ──────────
        cache_hit = bool(call_meta and call_meta.get('cache_hit'))
        cache_stale = bool(call_meta and call_meta.get('cache_stale'))
        if cache_stale:
            cache_stale_any = True
        call_fired = call_meta is not None and not cache_hit
        if page_quota_429:
            eff_units = 0
            page_error = 'quota_exceeded'
        else:
            eff_units = 0 if cache_hit else (1 if call_fired else 0)
        try:
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=eff_units, success=page_ok,
                error_code=None if page_ok else (page_error or 'unknown'),
                cache_hit=cache_hit, cache_stale=cache_stale,
            )
        except Exception as rec_err:
            log.warning("[%s] reconcile failed: %s", tool_name, rec_err)

        if cache_hit:
            pages_cached += 1
        elif call_fired:
            pages_fired += 1

        if page_quota_429:
            if page_idx == 0:
                return {
                    'kind': 'quota_exceeded', 'retry_after': 5,
                    'items': [], 'next_cursor': None, 'has_more': False,
                    'credits_remaining': None, 'meta': {},
                    'error_code': 'quota_exceeded', 'message': None,
                }
            quota_blocked = True
            break

        if not page_ok:
            if page_idx == 0:
                error_code = page_error or 'unknown'
                break
            # Mid-run failure: keep the pages already collected.
            page_error_note = page_error or 'unknown'
            log.warning(
                "[%s] page %d failed (%s) — returning %d item(s) from "
                "earlier pages", tool_name, page_idx + 1, page_error,
                len(items),
            )
            break

        page_items = extract_items(data or {})
        items.extend(page_items)
        credits_remaining = _credits_remaining(data or {})
        fetched = (call_meta or {}).get('fetched_at')
        if fetched:
            last_fetched_at = fetched
        next_cursor = extract_cursor(data or {})
        has_more = bool((data or {}).get('has_more')) or bool(next_cursor)
        ok = True
        error_code = None

        # Stop: budget reached, no further cursor, or an empty page.
        if len(items) >= limit or not next_cursor or not page_items:
            break

    meta: Dict[str, Any] = {
        'cacheHit': pages_cached > 0 and pages_fired == 0,
        'cacheStale': cache_stale_any,
        'pagesFired': pages_fired,
        'pagesCached': pages_cached,
    }
    if quota_blocked:
        meta['quotaBlocked'] = True
    if page_error_note:
        meta['pageError'] = page_error_note
    if last_fetched_at:
        meta['fetchedAt'] = last_fetched_at

    return {
        'kind': 'ok' if ok else 'error',
        'items': items[:limit],
        'next_cursor': next_cursor,
        'has_more': has_more,
        'credits_remaining': credits_remaining,
        'meta': meta,
        'error_code': error_code,
        'retry_after': None,
        'message': None,
    }
