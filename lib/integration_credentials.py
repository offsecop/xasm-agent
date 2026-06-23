"""
Integration Credentials Helper
Fetches API keys from backend integrations with agent access enabled.

DRP→ASM migration T2.6: adds `checkout_provider()` + `reconcile_call()` for
per-tenant quota leasing. Every non-LLM external provider that the agent
calls (HikerAPI, ScrapeCreators, twitterapi.io, IntelX, OTX_API,
GITHUB_SEARCH, VIRUSTOTAL, PHISHTANK, etc.) MUST go through these helpers
so the backend's ProviderQuotaService can enforce tenant-scoped caps
across all five agent containers.

The five agent containers' in-process rate limiters do NOT coordinate —
bypassing checkout() will trigger provider bans at scale.
See backend/src/modules/agent-engine/provider-quota.service.ts (T2.4).
"""

import os
import asyncio
import logging
import time
import aiohttp
from typing import Optional, Dict, Any, Tuple, Union

from .upstream_cache import CachedResponse, upstream_cache

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed exceptions for the checkout flow
# ---------------------------------------------------------------------------


class IntegrationCredentialsError(Exception):
    """Base for integration credential / quota errors."""


class IntegrationAuthError(IntegrationCredentialsError):
    """The agent's API key was rejected by the backend (HTTP 401)."""


class IntegrationServerError(IntegrationCredentialsError):
    """Backend 5xx or transport failure while reaching the quota endpoint."""


class QuotaExceededError(IntegrationCredentialsError):
    """The tenant's plan cap for this provider is exhausted (HTTP 429)."""

    def __init__(
        self,
        provider_key: str,
        retry_after: int,
        period_resets_at: Optional[str] = None,
        cap: Optional[int] = None,
        current_usage: Optional[int] = None,
    ):
        self.provider_key = provider_key
        self.retry_after = retry_after
        self.period_resets_at = period_resets_at
        self.cap = cap
        self.current_usage = current_usage
        super().__init__(
            f"Quota exceeded for {provider_key}: retry after {retry_after}s "
            f"(cap={cap}, used={current_usage}, resets={period_resets_at})"
        )


# ---------------------------------------------------------------------------
# Upstream retry helper — 429 / 5xx exponential backoff
# ---------------------------------------------------------------------------
#
# 2026-05-16 (Wave-Quota) — mirrors the original DRP `drp_client.py`
# RETRY_BACKOFF pattern. Every vendor wrapper (hiker_api, scrapecreators,
# twitterapi_io) wraps its upstream HTTP call through `upstream_request()`
# so a transient 429 or 5xx doesn't immediately reconcile success=false
# and burn a quota slot on the next cron tick's retry. Without this:
# upstream throttles ASM for ~3s -> wrapper reconciles failure -> scheduler
# retries within 60s -> upstream still throttling -> repeat -> dead requests
# pile up against the quota counter even though nothing produced findings.
#
# Retry policy:
#   - On HTTP 429: retry up to 3 times. Honor `Retry-After` header
#     (seconds) if present; otherwise use exponential backoff.
#   - On HTTP 502/503/504: retry up to 3 times with exponential backoff.
#   - On HTTP 500: retry once (some providers return transient 500s).
#   - On 4xx other than 429: NO retry. Caller error. Return immediately.
#   - On 2xx/3xx: return immediately.
#   - On transport exception: retry up to 3 times.
#
# Backoff sequence matches original DRP: 0.5s, 2s, 5s (max 7.5s total wait).

_RETRY_BACKOFF_SECONDS = (0.5, 2.0, 5.0)
_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}


async def upstream_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    provider_label: str = 'upstream',
    timeout_seconds: Optional[float] = None,
    # Phase-2B cache kwargs. Default None ⇒ caching disabled; behavior is
    # exactly the pre-cache path. The 3 vendor wrappers opt in by passing
    # cache_namespace + tenant_id; stub-mode call sites pass cache_namespace=None.
    cache_namespace: Optional[str] = None,
    cache_ttl_seconds: Optional[int] = None,
    stale_grace_seconds: Optional[int] = None,
    tenant_id: Optional[str] = None,
) -> Tuple[Union[aiohttp.ClientResponse, CachedResponse], Dict[str, Any]]:
    """Wrap an aiohttp request with 429/5xx backoff retry + optional TTL cache.

    Returns `(response, meta)` where `response` is either a real
    `aiohttp.ClientResponse` (cache miss / cache disabled) or a
    `CachedResponse` shim (cache hit). Both expose `.status`, `await .json()`,
    `await .text()`, and `await .release()` so callers don't branch.

    `meta` shape:
        {
          'fetched_at': float,   # unix seconds; cache hit -> ORIGINAL fetch ts
          'cache_hit':   bool,
          'cache_stale': bool,   # True only for stale-if-error fallback hits
        }

    Cache discipline (RFC 5861 — see `upstream_cache.py` for the full
    semantics):
      1. If `cache_namespace` is None, caching is OFF. Behavior is identical
         to the pre-cache implementation. Stub-mode callers pass None to
         keep the six-seam quota pipeline intact without caching synthesized
         payloads.
      2. GET only. Non-GET requests skip the cache entirely (cursor-keyed
         POSTs would explode the keyspace and twitterapi.io paginated calls
         already bypass via their cursor argument).
      3. On fresh hit: return `CachedResponse` + `meta(cache_hit=True,
         cache_stale=False, fetched_at=<original>)`. NO upstream call fires.
         Caller MUST still reconcile their lease with `cache_hit=True,
         units=0` so the six-seam ledger row is preserved.
      4. On miss: run the existing GET/POST retry loop. On 2xx with valid
         JSON: parse body, `upstream_cache.set(key, body, ttl_seconds=...,
         stale_grace_seconds=..., fetched_at=now)`. Return real response +
         `meta(cache_hit=False, cache_stale=False, fetched_at=now)`.
      5. On 5xx after all retries OR transport error: try
         `upstream_cache.get_stale(key)`. If hit, return `CachedResponse`
         + `meta(cache_hit=True, cache_stale=True, fetched_at=<original>)`.
         If no stale, propagate as today (raise transport error / return
         5xx response).
      6. On 4xx (non-429): no caching, propagate (caller error).

    `timeout_seconds` overrides the per-call total timeout. Phase 2A
    plumbed `timeoutSeconds` through the checkout response so platform
    operators can tune per-provider warm-up budgets without redeploying
    agents (HikerAPI's cold-start IG session warm-up can take ~77s on a
    fresh key — SMM `upstream.py:9-12`). When omitted, the session's
    pre-configured timeout applies.

    NOTE: this is the ONE place vendor wrappers can do upstream retry —
    do not re-implement per-wrapper backoff loops. See Wave-Quota note
    above for why a single retry policy across all 3 wrappers matters.
    """
    # --- Cache pre-check (GET + namespace only) ---------------------------
    # V3 tenant-isolation: only cache when a tenantId is present. Without it the
    # old key fell back to a shared "global" bucket, so two tenants' tenant-less
    # checkouts would read each other's cached upstream payloads. No tenant →
    # bypass the cache entirely (still functional, just uncached).
    cache_enabled = (
        cache_namespace is not None and method.upper() == 'GET' and bool(tenant_id)
    )
    cache_key: Optional[str] = None
    if cache_enabled:
        cache_key = upstream_cache.make_key(
            tenant_id, cache_namespace or '', method, url, params,
        )
        fresh = await upstream_cache.get_fresh(cache_key)
        if fresh is not None:
            cached_value, fetched_at = fresh
            logger.debug(
                f"[{provider_label}] cache HIT ns={cache_namespace} key={cache_key[:80]}"
            )
            return (
                CachedResponse(status=200, body=cached_value),
                {
                    'fetched_at': fetched_at,
                    'cache_hit': True,
                    'cache_stale': False,
                },
            )

    # --- Existing retry loop ---------------------------------------------
    per_call_timeout = (
        aiohttp.ClientTimeout(total=float(timeout_seconds))
        if timeout_seconds is not None
        else None
    )
    # `last_transport_exc` is assigned but only referenced from a defensive
    # tail block that Pyright proves is unreachable; assignments are kept
    # so the variable is in scope if a future refactor opens a non-returning
    # loop exit. Pyright "not accessed" warnings on these are intentional.
    last_transport_exc: Optional[BaseException] = None
    for attempt, wait_s in enumerate((0.0, *_RETRY_BACKOFF_SECONDS)):
        if wait_s > 0:
            await asyncio.sleep(wait_s)
        try:
            request_kwargs: Dict[str, Any] = {
                'headers': headers,
                'params': params,
                'json': json_body,
            }
            if per_call_timeout is not None:
                request_kwargs['timeout'] = per_call_timeout
            resp = await session.request(method, url, **request_kwargs)
        except aiohttp.ClientError as exc:
            # Transport error — log and retry if attempts remain.
            last_transport_exc = exc  # noqa: F841 — referenced from unreachable tail
            if attempt < len(_RETRY_BACKOFF_SECONDS):
                logger.warning(
                    f"[{provider_label}] transport error on attempt {attempt + 1}: {exc} — backing off"
                )
                continue
            # Retries exhausted on a transport error — try stale-if-error.
            if cache_enabled and cache_key is not None:
                stale = await upstream_cache.get_stale(cache_key)
                if stale is not None:
                    cached_value, fetched_at = stale
                    logger.warning(
                        f"[{provider_label}] transport error after retries — serving STALE "
                        f"(age={time.time() - fetched_at:.0f}s)"
                    )
                    return (
                        CachedResponse(status=200, body=cached_value),
                        {
                            'fetched_at': fetched_at,
                            'cache_hit': True,
                            'cache_stale': True,
                        },
                    )
            raise

        # 2xx/3xx — return immediately. Cache the parsed body on 2xx GET.
        if resp.status < 400:
            if cache_enabled and cache_key is not None and 200 <= resp.status < 300:
                # Parse and cache the body. We re-wrap as a CachedResponse so
                # the caller can still `await resp.json()` AND we don't have
                # to worry about whether aiohttp lets us read .json() twice.
                now = time.time()
                try:
                    body = await resp.json()
                    await resp.release()
                    await upstream_cache.set(
                        cache_key,
                        body,
                        fetched_at=now,
                        ttl_seconds=cache_ttl_seconds,
                        stale_grace_seconds=stale_grace_seconds,
                    )
                    return (
                        CachedResponse(
                            status=resp.status,
                            body=body,
                            headers=dict(resp.headers),
                        ),
                        {
                            'fetched_at': now,
                            'cache_hit': False,
                            'cache_stale': False,
                        },
                    )
                except (aiohttp.ContentTypeError, ValueError, TypeError) as exc:
                    # Non-JSON body — fall through and return the raw
                    # response. No cache write. Caller handles via .text().
                    logger.debug(
                        f"[{provider_label}] 2xx non-JSON body, skipping cache: {exc}"
                    )
                    # resp was released in the try block above on success;
                    # on the JSON-parse exception path we haven't released
                    # yet, so the raw response is still usable by the caller.
            return resp, {
                'fetched_at': time.time(),
                'cache_hit': False,
                'cache_stale': False,
            }
        # 4xx other than 429 — caller error, do not retry, do not cache.
        if 400 <= resp.status < 500 and resp.status != 429:
            return resp, {
                'fetched_at': time.time(),
                'cache_hit': False,
                'cache_stale': False,
            }
        # 429 / 5xx in the retryable set — back off and retry if attempts remain.
        if resp.status in _RETRYABLE_STATUSES and attempt < len(_RETRY_BACKOFF_SECONDS):
            # Honor Retry-After if the server told us how long to wait.
            retry_after_header = resp.headers.get('Retry-After')
            if retry_after_header:
                try:
                    override = float(retry_after_header)
                    # Cap the override to avoid a malicious provider tying us up.
                    override = min(override, 10.0)
                    # Use override on the NEXT iteration by overwriting the wait
                    # via a fresh sleep here (we already slept `wait_s` for this
                    # attempt). The next iteration's `wait_s` from the tuple is
                    # additive — that's fine; treat Retry-After as a floor.
                    await asyncio.sleep(override)
                    logger.info(
                        f"[{provider_label}] HTTP {resp.status} with Retry-After={override}s — backing off"
                    )
                except (ValueError, TypeError):
                    pass
            else:
                logger.info(
                    f"[{provider_label}] HTTP {resp.status} on attempt {attempt + 1} — backing off"
                )
            await resp.release()  # free the connection before the next attempt
            continue
        # 5xx outside retryable set, or retries exhausted — try stale-if-error.
        if cache_enabled and cache_key is not None and resp.status >= 500:
            stale = await upstream_cache.get_stale(cache_key)
            if stale is not None:
                cached_value, fetched_at = stale
                logger.warning(
                    f"[{provider_label}] HTTP {resp.status} after retries — serving STALE "
                    f"(age={time.time() - fetched_at:.0f}s)"
                )
                await resp.release()
                return (
                    CachedResponse(status=200, body=cached_value),
                    {
                        'fetched_at': fetched_at,
                        'cache_hit': True,
                        'cache_stale': True,
                    },
                )
        return resp, {
            'fetched_at': time.time(),
            'cache_hit': False,
            'cache_stale': False,
        }

    # The retry loop above always returns or raises on every code path
    # (Pyright proves this via reportUnreachableCode). The defensive block
    # below is intentionally unreachable — kept only as a belt-and-braces
    # guarantee that any future refactor that adds a non-returning loop exit
    # still raises rather than falling off the end with `None`.
    if last_transport_exc is not None:  # pyright: ignore[reportUnreachableCode]
        raise last_transport_exc
    raise IntegrationServerError(  # pyright: ignore[reportUnreachableCode]
        f"[{provider_label}] retries exhausted with no response"
    )


# ---------------------------------------------------------------------------
# Backend URL + agent API key resolution
# ---------------------------------------------------------------------------

# Per-instance identity (WP4): the runtime key is issued by /agents/enroll/tenant
# at boot and held only in this process. agent_core_rest.Agent publishes it here
# via set_runtime_api_key() so per-tool ProviderQuotaService checkouts
# authenticate as the SAME enrolled instance (one identity for jobs + leases).
# There is no static AGENT_API_KEY / volume key file any more.
_runtime_api_key: Optional[str] = None


def set_runtime_api_key(api_key: Optional[str]) -> None:
    """Publish (or clear) this instance's enrolled per-instance API key."""
    global _runtime_api_key
    _runtime_api_key = api_key


# Phase 3 / WP6 — the active job id, published per-job by the agent core while a
# tool runs (set_current_job_id). Sent as the `X-Job-Id` header on every
# money/secrets path (checkout, credentials-for-agent, /agents/config, the LLM
# relay). For a BOOTSTRAP agent the backend re-derives the billing tenant from
# THIS job (ownership-verified) instead of the agent's SYSTEM tenant; for a
# dedicated agent the header is ignored. ContextVar so concurrent jobs on one
# instance never cross-pollinate their job id.
from contextvars import ContextVar  # noqa: E402

_current_job_id: ContextVar[Optional[str]] = ContextVar('current_job_id', default=None)


def set_current_job_id(job_id: Optional[str]) -> None:
    """Publish (or clear) the job id the current tool execution is acting on."""
    _current_job_id.set(job_id)


def _job_id_headers() -> Dict[str, str]:
    """X-Job-Id header for the active job, or {} when none is set."""
    jid = _current_job_id.get()
    return {'X-Job-Id': jid} if jid else {}


def _resolve_backend_config() -> Optional[Dict[str, str]]:
    """Resolve backend URL + this instance's enrolled agent API key.

    The key comes solely from the in-process enrolled runtime key published by
    the agent core (set_runtime_api_key). Returns None if the instance has not
    yet enrolled, in which case the caller surfaces `no_credentials`.
    """
    if not _runtime_api_key:
        logger.warning("[Credentials] Instance not yet enrolled — no runtime API key")
        return None

    api_url = os.environ.get('API_URL') or os.environ.get('AGENT_API_URL', 'http://backend:3001/api')
    return {'api_url': api_url, 'agent_api_key': _runtime_api_key}


# ---------------------------------------------------------------------------
# Legacy: simple credential fetch (kept unchanged for backwards compat)
# ---------------------------------------------------------------------------


async def get_integration_credentials(provider: str) -> Optional[Dict[str, str]]:
    """
    Fetch integration credentials from the backend.

    The integration must have `enableAgentAccess` set to true.

    Args:
        provider: Integration provider name (e.g., 'SHODAN')

    Returns:
        Dict with credentials (e.g., {'apiKey': '...'}) or None if not available.

    NOTE: This does NOT consume quota. Use `checkout_provider()` for any
    rate-limited external API call. This helper remains here for tools
    (currently just Shodan) that have not yet been migrated.
    """
    cfg = _resolve_backend_config()
    if not cfg:
        return None

    url = f"{cfg['api_url']}/integrations/{provider.upper()}/credentials-for-agent"

    try:
        async with aiohttp.ClientSession() as session:
            headers = {'X-API-Key': cfg['agent_api_key'], **_job_id_headers()}
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('credentials')
                elif response.status == 403:
                    logger.info(f"[Credentials] Agent access not enabled for {provider}")
                    return None
                elif response.status == 404:
                    logger.info(f"[Credentials] Integration {provider} not found")
                    return None
                else:
                    error_text = await response.text()
                    logger.warning(
                        f"[Credentials] Error fetching {provider} credentials: "
                        f"{response.status} - {error_text}"
                    )
                    return None
    except Exception as e:
        logger.warning(f"[Credentials] Exception fetching {provider} credentials: {e}")
        return None


async def get_shodan_api_key() -> Optional[str]:
    """
    Get Shodan API key from integration or environment.

    Checks in order:
    1. SHODAN_API_KEY environment variable
    2. Backend integration with agent access enabled

    Returns:
        Shodan API key or None
    """
    api_key = os.environ.get('SHODAN_API_KEY')
    if api_key:
        return api_key

    credentials = await get_integration_credentials('SHODAN')
    if credentials:
        return credentials.get('apiKey')

    return None


# ---------------------------------------------------------------------------
# DRP→ASM T2.6: checkout / reconcile (quota-bearing)
# ---------------------------------------------------------------------------


async def checkout_provider(
    provider_key: str,
    requested_units: int = 1,
    *,
    session: Optional[aiohttp.ClientSession] = None,
) -> Dict[str, Any]:
    """
    Reserve quota units for a tenant-scoped provider call and obtain the
    decrypted API key + a lease token.

    The backend authenticates the calling agent via X-API-Key and resolves
    the tenant from the agent record — callers do NOT pass tenant_id.

    Args:
        provider_key: IntegrationProvider enum value (e.g. 'HIKER_API').
        requested_units: Quota units to reserve (default 1).
        session: Optional aiohttp.ClientSession to reuse. If None, a new one
            is created and closed for this call.

    Returns:
        Dict with keys:
          - apiKey (str): the decrypted upstream API key
          - leaseToken (str): opaque token to pass to reconcile_call()
          - periodResetsAt (str): ISO-8601 timestamp
          - baseUrl (str, optional): per-tenant override of the upstream base
            URL (Phase 2A — fall back to the wrapper's vendor default when
            absent so legacy integrations without the field still work).
          - timeoutSeconds (int, optional): per-tenant override of the
            per-call HTTP timeout (Phase 2A — same fallback contract).
          - tier (str, optional): HikerAPI plan tier, informational only.
          - cacheTtlSeconds (int, optional): Phase 2B — base TTL for the
            upstream response cache. Vendor wrappers fall back to vendor
            defaults when absent.
          - cacheNamespaceTtls (dict, optional): Phase 2B — per-namespace
            TTL overrides (e.g. `{"HikerAPI:user.by.username": 3600}`).
          - staleGraceSeconds (int, optional): Phase 2B — stale-if-error
            grace window per RFC 5861.
          - tenantId (str, optional): Phase 2B — tenant identifier used to
            namespace cache keys so a tenant cannot read another tenant's
            cached upstream payloads. None falls back to the literal
            `"global"` prefix (legacy + dev-only path).

    Raises:
        QuotaExceededError: on HTTP 429
        IntegrationAuthError: on HTTP 401
        IntegrationServerError: on 4xx/5xx other than 401/429, or transport error
    """
    cfg = _resolve_backend_config()
    if not cfg:
        raise IntegrationServerError("Agent API key not configured")

    url = f"{cfg['api_url']}/integrations/{provider_key.upper()}/checkout"
    headers = {
        'X-API-Key': cfg['agent_api_key'],
        'Content-Type': 'application/json',
        # WP6 — lets the backend re-key billing tenant for a bootstrap agent.
        **_job_id_headers(),
    }
    body = {'requestedUnits': int(requested_units)}

    owns_session = session is None
    if owns_session:
        session = aiohttp.ClientSession()

    try:
        async with session.post(url, headers=headers, json=body) as resp:
            if resp.status == 200:
                data = await resp.json()
                # Phase 2A: backend now optionally returns `baseUrl`,
                # `timeoutSeconds`, and (HikerAPI only) `tier` alongside the
                # apiKey/leaseToken pair. Wrappers fall back to their own
                # vendor-default constants when these are absent.
                return {
                    'apiKey': data.get('apiKey'),
                    'leaseToken': data.get('leaseToken'),
                    'periodResetsAt': data.get('periodResetsAt'),
                    'baseUrl': data.get('baseUrl'),
                    'timeoutSeconds': data.get('timeoutSeconds'),
                    'tier': data.get('tier'),
                    # Phase 2B — optional cache-control fields. All four
                    # default to None; wrappers fall back to vendor defaults
                    # when absent so legacy integration rows still work.
                    'cacheTtlSeconds': data.get('cacheTtlSeconds'),
                    'cacheNamespaceTtls': data.get('cacheNamespaceTtls'),
                    'staleGraceSeconds': data.get('staleGraceSeconds'),
                    'tenantId': data.get('tenantId'),
                }
            elif resp.status == 429:
                # Try to surface the structured QuotaExceeded payload + Retry-After
                retry_after_header = resp.headers.get('Retry-After')
                try:
                    payload = await resp.json()
                except Exception:
                    payload = {}
                retry_after = int(
                    retry_after_header
                    or payload.get('retryAfter')
                    or 60
                )
                raise QuotaExceededError(
                    provider_key=payload.get('providerKey', provider_key.upper()),
                    retry_after=retry_after,
                    period_resets_at=payload.get('periodResetsAt'),
                    cap=payload.get('cap'),
                    current_usage=payload.get('currentUsage'),
                )
            elif resp.status == 401:
                raise IntegrationAuthError(
                    f"Agent API key rejected by backend on checkout({provider_key})"
                )
            else:
                error_text = await resp.text()
                raise IntegrationServerError(
                    f"checkout({provider_key}) HTTP {resp.status}: {error_text[:200]}"
                )
    except aiohttp.ClientError as e:
        raise IntegrationServerError(
            f"checkout({provider_key}) transport error: {e}"
        ) from e
    finally:
        if owns_session and session is not None:
            await session.close()


async def reconcile_call(
    provider_key: str,
    lease_token: str,
    *,
    units: Optional[int] = None,
    cost_usd: Optional[float] = None,
    success: bool = True,
    error_code: Optional[str] = None,
    cache_hit: Optional[bool] = None,
    cache_stale: Optional[bool] = None,
    session: Optional[aiohttp.ClientSession] = None,
) -> None:
    """
    Finalize a lease started by `checkout_provider()`. Idempotent on the
    backend; this helper fires and ignores 200.

    Failure to reconcile is LOGGED but not raised — we have already made
    the provider call. The lease will be aged out by the backend's
    rolling-window logic eventually, so the worst case is over-counting
    a single call against the cap.

    Args:
        provider_key: same provider key passed to checkout (used only in
            the path for symmetry; the lease itself is keyed by
            lease_token).
        lease_token: the token returned from checkout_provider().
        units: final unit count actually consumed (defaults to backend's
            stored value from checkout).
        cost_usd: actual USD cost reported by the provider, if available.
        success: whether the upstream call succeeded.
        error_code: short error tag if success is False.
        session: optional aiohttp.ClientSession to reuse.
    """
    cfg = _resolve_backend_config()
    if not cfg:
        logger.warning(
            f"[Quota] Cannot reconcile {provider_key} lease: "
            f"agent API key not configured"
        )
        return

    url = f"{cfg['api_url']}/integrations/{provider_key.upper()}/reconcile"
    headers = {
        'X-API-Key': cfg['agent_api_key'],
        'Content-Type': 'application/json',
    }
    body: Dict[str, Any] = {
        'leaseToken': lease_token,
        'success': bool(success),
    }
    if units is not None:
        body['units'] = int(units)
    if cost_usd is not None:
        body['costUsd'] = float(cost_usd)
    if error_code:
        body['errorCode'] = str(error_code)[:128]
    # Phase 2B — optional cache attribution. Backend writes provider_call_logs
    # rows with cacheHit=true / costUsd=0 when a hit is reported so the audit
    # row is preserved (six-seam invariant) but no platform cost is incurred.
    if cache_hit is not None:
        body['cacheHit'] = bool(cache_hit)
    if cache_stale is not None:
        body['cacheStale'] = bool(cache_stale)

    owns_session = session is None
    if owns_session:
        session = aiohttp.ClientSession()

    try:
        async with session.post(url, headers=headers, json=body) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                logger.warning(
                    f"[Quota] Reconcile {provider_key} returned HTTP "
                    f"{resp.status}: {error_text[:200]}"
                )
    except Exception as e:
        # Reconcile failures are NEVER fatal. The upstream call already
        # happened — losing the reconcile is annoying but not catastrophic.
        logger.warning(f"[Quota] Reconcile {provider_key} failed: {e}")
    finally:
        if owns_session and session is not None:
            await session.close()
