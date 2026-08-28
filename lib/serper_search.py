"""Shared Serper.dev SERP plumbing (#981 wiring, extracted 2026-07-10).

Moved verbatim from `tools/brand_monitor_vip_exposure.py` so the brand-mention
sentiment collector (`serper:brand_mentions`) can reuse the EXACT quota-safe
per-page-metering contract instead of duplicating it: checkout a
ProviderQuotaService lease → POST → reconcile, ONE bracket per metered page,
fail-closed (a blocked/broken sweep is NEVER reported swept-clean).

Consumers:
  - tools/brand_monitor_vip_exposure.py  (VIP-exposure threat hunting)
  - tools/serper_brand_mentions.py       (brand-mention sentiment collection)
"""

from __future__ import annotations

import asyncio
import sys
import os
from typing import Any, Dict, List, Optional

_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

import aiohttp

from lib.integration_credentials import (
    checkout_provider,
    reconcile_call,
    upstream_request,
    QuotaExceededError,
    IntegrationAuthError,
    IntegrationServerError,
)

# #981 — sanctioned SERP provider key (the enum value the ProviderQuotaService
# checks; concrete vendor = Serper.dev, discriminated by settings.provider).
SERP_PROVIDER_KEY = 'SERP_SEARCH'

# SSRF: the Serper endpoint is PINNED here — the plumbing NEVER uses the
# checkout-returned baseUrl (the catalog omits `baseUrl` from optionalFields),
# so an operator cannot repoint SERP_SEARCH at an internal host to exfiltrate
# the key or drive blind server-side POSTs.
SERPER_ENDPOINT = 'https://google.serper.dev/search'
# Depth lever: `num>10` does NOT deepen (Serper caps a page at 10 results); the
# `page` parameter is the only way to reach results 11+, and EACH page is a
# separate metered call. So we page, we do not inflate `num`.
SERPER_RESULTS_PER_PAGE = 10
# Per-cohort depth policy (#981 §5): pinpoint dorks (LinkedIn/paste/data-broker)
# have a worthless tail → 1 page; discovery dorks (combosquat/brand-abuse/…)
# paginate loop-until-dry, bounded.
PINPOINT_MAX_PAGES = 1
DISCOVERY_MAX_PAGES = 3

# #1504 — vendor blink: Serper intermittently returns HTTP 200 with ZERO
# organic results for a query that provably has them (live-verified
# 2026-07-22: same query + same `tbs`, four consecutive calls → 0, 10, 9, 6
# organic; a `qdr:y` probe returned 0 then 10 on retest — each empty response
# still bills a credit). An unretried blink silently empties a whole cohort
# and is indistinguishable from a genuinely quiet period. Bounded
# retry-on-empty lives at THIS seam (both consumers share `dispatch_serper`):
#   - PAGE 1 ONLY — an empty page >1 is the normal loop-until-dry tail
#     (`execute_serp_queries`), retrying it burns credits for nothing;
#   - each retry is a FRESH checkout→POST→reconcile bracket (metering is
#     never bypassed; every attempt is a `ProviderCallLog` row);
#   - ≤ EMPTY_PAGE1_MAX_RETRIES per page-1 call, linear backoff;
#   - a per-SWEEP budget bounds amplification: worst case
#     +EMPTY_RETRY_SWEEP_BUDGET credits per sweep. Without it a per-page
#     retry could add 2 × MAX_SERP_PAGES_PER_VIP(30) = 60 credits to a VIP
#     sweep; with it a mention scan's natural ceiling moves 11 → ≤17 and a
#     VIP sweep's 30 → ≤36. Queries that are GENUINELY empty every scan
#     draw from (and are capped by) the same budget — the retry can never
#     mask a real empty forever, it only delays reporting it by ≤2 attempts.
EMPTY_PAGE1_MAX_RETRIES = 2
EMPTY_RETRY_SWEEP_BUDGET = 6
EMPTY_RETRY_BACKOFF_SECONDS = 1.5  # attempt n sleeps n × this


def new_empty_retry_budget() -> Dict[str, int]:
    """Fresh per-sweep retry-on-empty budget (#1504). A sweep creates ONE and
    passes it to every `dispatch_serper` call so total blink-retry spend is
    bounded sweep-wide, not per page."""
    return {'remaining': EMPTY_RETRY_SWEEP_BUDGET}

# Registrable-domain (eTLD+1) helper: the small set of multi-label public
# suffixes we care about. A full PSL is overkill for SERP triage; this covers
# the common ccTLD second levels so `foo.co.uk` → `foo.co.uk`, not `co.uk`.
_MULTI_LEVEL_TLDS = {
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'co.jp', 'com.au', 'net.au',
    'org.au', 'co.nz', 'com.br', 'com.mx', 'co.in', 'co.za', 'com.sg',
    'com.hk', 'com.tr', 'com.cn', 'com.tw',
}


class SerpNotConfigured(Exception):
    """No usable SERP_SEARCH integration (404 no-integration / 403 agent-access
    off). NOT a failure — the sweep simply isn't available, so the caller falls
    through to the existing behaviour (never a false empty-clean)."""


class SerpSweepFailed(Exception):
    """A CONFIGURED SERP provider was actively broken mid-sweep (401 revoked key,
    429 quota, 402 cost-breaker, persistent 5xx). Scan-invalidating: the caller
    must FAIL the job, never report a clean zero-findings result."""


def registrable_domain(host: str) -> str:
    """eTLD+1 of a hostname (best-effort, PSL-lite). '' on empty input."""
    host = (host or '').lower().strip().strip('.').split(':')[0]
    if not host:
        return ''
    labels = host.split('.')
    if len(labels) <= 2:
        return host
    if '.'.join(labels[-2:]) in _MULTI_LEVEL_TLDS:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


async def dispatch_serper(
    query: str,
    page: int,
    session: aiohttp.ClientSession,
    timeout_seconds: Optional[float] = None,
    tbs: Optional[str] = None,
    gl: Optional[str] = None,
    empty_retry_budget: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Live Serper.dev dispatch for one metered page, with bounded
    retry-on-empty for the page-1 vendor blink (#1504 — see the constants
    block above for the verified behavior and the budget arithmetic).

    `empty_retry_budget` is the per-SWEEP budget dict from
    `new_empty_retry_budget()`; pass ONE instance across a whole sweep.
    Omitted → a fresh per-call budget (standalone calls stay bounded).
    When a page-1 dispatch returned zero organic hits and was retried, the
    returned dict additionally carries `empty_retries: <attempts>` — the
    observable that distinguishes "vendor returned 0 organic N times" from
    "query returned results first try".
    """
    result = await _dispatch_serper_once(
        query, page, session, timeout_seconds=timeout_seconds, tbs=tbs, gl=gl,
    )
    if page != 1:
        return result
    budget = empty_retry_budget if empty_retry_budget is not None \
        else new_empty_retry_budget()
    retries = 0
    while (
        not result['hits']
        and not result['unswept']
        and retries < EMPTY_PAGE1_MAX_RETRIES
        and budget.get('remaining', 0) > 0
    ):
        retries += 1
        budget['remaining'] = budget.get('remaining', 0) - 1
        await asyncio.sleep(EMPTY_RETRY_BACKOFF_SECONDS * retries)
        result = await _dispatch_serper_once(
            query, page, session,
            timeout_seconds=timeout_seconds, tbs=tbs, gl=gl,
        )
    if retries:
        result['empty_retries'] = retries
    return result


async def _dispatch_serper_once(
    query: str,
    page: int,
    session: aiohttp.ClientSession,
    timeout_seconds: Optional[float] = None,
    tbs: Optional[str] = None,
    gl: Optional[str] = None,
) -> Dict[str, Any]:
    """ONE metered Serper page (#981 §3). Per the issue's
    per-page-metering contract: checkout a lease → POST → reconcile, one bracket
    per page, so a `ProviderCallLog` row exists per page and the DAILY cap can
    halt a runaway sweep at a page boundary.

    `tbs` (optional) is Google's time-bounded-search restriction (e.g.
    'qdr:m') — passed through verbatim when set so recency-windowed cohorts
    (brand-mention sentiment) return dated, recent rows.

    `gl` (optional, #1383) is Serper's country bias (ISO-3166 alpha-2, e.g.
    'ca') — included in the body only when set, so a ccTLD-market brand's
    regional results (bbb.org/ca/..., ccTLD review profiles) can surface.
    Callers that pass nothing get byte-identical request bodies to before.

    Returns `{'hits': [...], 'unswept': bool}`; each hit carries
    `url`/`title`/`snippet` and, when the vendor reports one, `date` (raw
    Serper string — absolute or relative). Error handling (fail-closed —
    NEVER a swept-clean empty page on failure):
      - checkout 404/403 no-integration       → `SerpNotConfigured` (fall-through)
      - checkout/HTTP 401, 402, 403, 429       → `SerpSweepFailed` (abort sweep)
      - HTTP 400 (free-tier filetype block)    → `unswept=True` (this page only)
      - HTTP 404/5xx/other, transport, JSON    → `unswept=True` (this page only;
        an all-unswept sweep then fails closed in the caller)
    NEVER logs or returns the decrypted apiKey."""
    try:
        lease = await checkout_provider(SERP_PROVIDER_KEY, requested_units=1, session=session)
    except IntegrationAuthError:
        raise SerpSweepFailed('serp_auth_failed')       # 401 revoked/bad key
    except QuotaExceededError:
        raise SerpSweepFailed('serp_quota_exceeded')    # 429 quota exhausted
    except IntegrationServerError as exc:
        msg = str(exc)
        if any(m in msg for m in ('HTTP 404', 'HTTP 403', 'No active', 'not enabled', 'Unknown provider')):
            raise SerpNotConfigured(msg)                # not configured / agent-access off
        raise SerpSweepFailed('serp_server_error')      # 402 cost-breaker / 5xx / transport

    api_key = lease.get('apiKey')
    lease_token = lease.get('leaseToken')
    if not api_key or not lease_token:
        raise SerpSweepFailed('serp_no_key')
    eff_timeout = timeout_seconds or lease.get('timeoutSeconds') or 30

    ok = True
    err_code: Optional[str] = None
    unswept = False
    hits: List[Dict[str, Any]] = []
    resp = None
    try:
        # Endpoint is PINNED (SSRF) — the leased baseUrl is deliberately ignored.
        body: Dict[str, Any] = {'q': query, 'num': SERPER_RESULTS_PER_PAGE, 'page': page}
        if tbs:
            body['tbs'] = tbs
        if gl:
            body['gl'] = gl
        resp, _ = await upstream_request(
            session, 'POST', SERPER_ENDPOINT,
            headers={'X-API-KEY': api_key, 'Content-Type': 'application/json'},
            json_body=body,
            provider_label='serper',
            timeout_seconds=eff_timeout,
        )
        status = getattr(resp, 'status', 0)
        if status == 400:
            # Free-tier config-filetype block → unswept (low-confidence), the
            # sweep of THIS query is NOT a clean zero. Never empty-clean.
            ok = False
            err_code = 'serp_http_400'
            unswept = True
        elif status == 401:
            ok = False
            err_code = 'serp_http_401'
            raise SerpSweepFailed('serp_http_401')       # key revoked mid-sweep
        elif status in (402, 403):
            # Cost-breaker (402) / forbidden (403) — the vendor is CUT OFF; every
            # further call will fail the same way, so abort the whole sweep.
            ok = False
            err_code = f'serp_http_{status}'
            raise SerpSweepFailed(f'serp_http_{status}')
        elif status == 429:
            ok = False
            err_code = 'serp_http_429'
            raise SerpSweepFailed('serp_http_429')
        elif status >= 400:
            # 404 / 5xx / other — upstream_request already retried 5xx; a
            # persistent failure here is NOT a clean page. Mark this page
            # `unswept` so the sweep can never be reported swept-clean on an
            # upstream error (an all-unswept sweep fails closed in the caller).
            ok = False
            err_code = f'serp_http_{status}'
            unswept = True
        else:
            data = await resp.json()
            for item in (data.get('organic') or []):
                link = item.get('link')
                if not link:
                    continue
                hit: Dict[str, Any] = {
                    'url': link,
                    'title': item.get('title', '') or '',
                    'snippet': item.get('snippet', '') or '',
                }
                # Serper's optional per-result date ("Jun 5, 2026" or
                # "2 weeks ago") — passed through RAW; the backend's
                # observed-at parser handles both forms and never guesses.
                if item.get('date'):
                    hit['date'] = str(item['date'])
                # #1368 — Serper's optional structured review-rating fields
                # (present on review-site profile results, e.g. Trustpilot
                # /review/ pages). Numbers only, passed through verbatim so
                # ingestion can stamp CONFIRMED BrandReviewProfile rows.
                # Booleans are excluded (bool is an int subclass in Python).
                for _rk in ('rating', 'ratingCount'):
                    _rv = item.get(_rk)
                    if isinstance(_rv, (int, float)) and not isinstance(_rv, bool):
                        hit[_rk] = _rv
                hits.append(hit)
    except SerpSweepFailed:
        raise
    except Exception:
        # Transport error / timeout / malformed JSON — NEVER a clean page.
        ok = False
        err_code = 'serp_dispatch_error'
        unswept = True
    finally:
        if resp is not None:
            try:
                await resp.release()
            except Exception:
                pass
        # ONE reconcile per page, always — with success + error_code attribution
        # so 4xx/5xx feed the reconciled-failure throttle path.
        try:
            await reconcile_call(
                SERP_PROVIDER_KEY, lease_token,
                units=1, success=ok, error_code=err_code, session=session,
            )
        except Exception:
            pass
    return {'hits': hits, 'unswept': unswept}


async def execute_serp_queries(
    query_specs: List[Dict[str, Any]],
    agent=None,
    max_pages: int = 30,
    _dispatch=None,
) -> Dict[str, Any]:
    """Execute cohort-tagged SERP query specs through an injectable per-page
    dispatch `(query, page) -> {'hits': [...], 'unswept': bool}`.

    Per-cohort depth: pinpoint = 1 page; discovery = loop-until-dry bounded by
    DISCOVERY_MAX_PAGES. A GLOBAL `max_pages` hard cap bounds worst-case metered
    spend per scan. Fail-closed contract:
      - `_dispatch is None`                       → status 'unswept_no_provider'
      - first dispatch raises `SerpNotConfigured` → status 'unswept_no_provider'
      - queries blocked/broken (400 free-tier, 404/5xx, transport) and NOTHING
        swept clean                               → status 'unswept' (caller FAILs)
      - `SerpSweepFailed` (401/402/403/429)       → propagates (caller FAILs job)
    NEVER returns `{swept:True, results:[]}` from a failed/blocked-only sweep.
    The caller treats BOTH a raised `SerpSweepFailed` AND a returned status
    'unswept' as a job failure — only 'unswept_no_provider' falls through.
    """
    if _dispatch is None:
        if agent:
            agent.report_progress(
                current_operation='SERP execution skipped: no SERP provider configured',
            )
        return {'swept': False, 'status': 'unswept_no_provider', 'results': []}

    results: List[Dict[str, Any]] = []
    pages_used = 0
    swept_any = False
    unswept_any = False
    diagnostics = {
        'pagesUsed': 0, 'queriesRun': 0, 'unsweptQueries': 0, 'truncated': False,
        # #1504 — vendor-blink observability: pages whose page-1 came back
        # with zero organic and was retried, and the metered retry attempts
        # spent (bounded by EMPTY_RETRY_SWEEP_BUDGET when the dispatch shares
        # a sweep budget). Non-zero here = "the vendor blinked", distinct
        # from a genuinely quiet period.
        'emptyRetriedPages': 0, 'emptyRetriesUsed': 0,
    }

    try:
        for spec in query_specs:
            if pages_used >= max_pages:
                diagnostics['truncated'] = True
                break
            query = spec.get('query') if isinstance(spec, dict) else spec
            kind = spec.get('kind', 'discovery') if isinstance(spec, dict) else 'discovery'
            cohort = spec.get('cohort') if isinstance(spec, dict) else None
            if not query:
                continue
            per_cohort_max = PINPOINT_MAX_PAGES if kind == 'pinpoint' else DISCOVERY_MAX_PAGES
            diagnostics['queriesRun'] += 1
            page = 1
            while page <= per_cohort_max and pages_used < max_pages:
                pages_used += 1
                page_result = await _dispatch(query, page)
                try:
                    _empty_retries = int((page_result or {}).get('empty_retries') or 0)
                except (TypeError, ValueError):
                    _empty_retries = 0
                if _empty_retries > 0:
                    diagnostics['emptyRetriedPages'] += 1
                    diagnostics['emptyRetriesUsed'] += _empty_retries
                if (page_result or {}).get('unswept'):
                    unswept_any = True
                    diagnostics['unsweptQueries'] += 1
                    break  # a blocked query — don't paginate it, never clean it
                swept_any = True
                hits = (page_result or {}).get('hits') or []
                new_hits = 0
                for hit in hits:
                    if not (hit or {}).get('url'):
                        continue
                    hit['_cohort'] = cohort
                    hit['_query'] = query
                    hit['_page'] = page
                    results.append(hit)
                    new_hits += 1
                # loop-until-dry: stop on pinpoint, or when a discovery page dries
                # up (no new hits) or returns a short final page.
                if kind == 'pinpoint' or new_hits == 0 or len(hits) < SERPER_RESULTS_PER_PAGE:
                    break
                page += 1
    except SerpNotConfigured:
        if not swept_any and not results:
            if agent:
                agent.report_progress(
                    current_operation='SERP provider not configured; skipping SERP sweep',
                )
            return {'swept': False, 'status': 'unswept_no_provider', 'results': []}
        # Configured then vanished mid-sweep → treat as a scan-invalidating fail.
        raise SerpSweepFailed('serp_not_configured_midsweep')

    diagnostics['pagesUsed'] = pages_used
    # Fail-closed: a sweep whose ONLY outcome was blocked (400) queries is NOT a
    # clean zero-findings result.
    if not swept_any and unswept_any:
        return {'swept': False, 'status': 'unswept', 'results': [], 'diagnostics': diagnostics}
    if not swept_any:
        return {'swept': False, 'status': 'unswept_no_provider', 'results': results, 'diagnostics': diagnostics}
    return {'swept': True, 'status': 'swept', 'results': results, 'diagnostics': diagnostics}
