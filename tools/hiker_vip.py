"""HikerAPI VIP Composite Tool — DRP P0+P1 migration Phase 5b.

Implements `hiker:vip_composite`. Tighter brand-composite cousin for
individual / executive handles:

  HK.1.vip — VIP handle-permutation existence check (~9 calls). 404s
             become squat_candidate findings.
  HK.2.vip — fbsearch.topsearch + fbsearch.accounts on the VIP's full
             name (2 calls).

Hashtags and places are intentionally NOT scanned — irrelevant for
individuals per Phase 4 SMM playbook §2. Total budget: ~11 calls.

HikerAPI bills 1 credit per call including 404s. A single permutation
404 / 403 (private account) MUST NOT poison the gather.
"""

from __future__ import annotations

import sys
import os
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set

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
from lib.wrapper_helpers import (
    first as _first,
    similarity as _similarity,
    build_account as _build_account,
    classify_account as _classify_account,
    B_LEGIT,
    B_BRAND_ADJ,
    B_IMPERSONATOR,
    B_SQUAT,
)

logger = logging.getLogger(__name__)

PROVIDER_KEY = 'HIKER_API'
BASE_URL = 'https://api.hikerapi.com'
DEFAULT_TIMEOUT = 90
STUB_API_KEY = 'sk-dev-stub-hiker'

NS_USER = 'HikerAPI:user.by.username'
NS_TOPSEARCH = 'HikerAPI:fbsearch.topsearch'
NS_ACCOUNTS = 'HikerAPI:fbsearch.accounts'

TTL_USER = 3600
TTL_TOPSEARCH = 1800
TTL_ACCOUNTS = 300


async def _safe_get(
    session: aiohttp.ClientSession,
    headers: Dict[str, str],
    url: str,
    params: Dict[str, Any],
    *,
    provider_label: str,
    timeout_seconds: float,
    cache_namespace: str,
    cache_ttl: int,
    stale_grace: Optional[int],
    tenant_id: Optional[str],
) -> Tuple[Optional[Dict[str, Any]], str, Dict[str, Any]]:
    try:
        resp, meta = await upstream_request(
            session, 'GET', url,
            headers=headers, params=params,
            provider_label=provider_label,
            timeout_seconds=timeout_seconds,
            cache_namespace=cache_namespace,
            cache_ttl_seconds=cache_ttl,
            stale_grace_seconds=stale_grace,
            tenant_id=tenant_id,
        )
    except aiohttp.ClientError as exc:
        logger.warning(f"[{provider_label}] transport error: {exc}")
        return None, 'error', {'cache_hit': False, 'cache_stale': False, 'fetched_at': None}

    try:
        if resp.status == 200:
            try:
                data = await resp.json()
            except Exception:
                return None, 'error', meta
            return (data if isinstance(data, dict) else None), 'ok', meta
        if resp.status == 404:
            return None, 'not_found', meta
        if resp.status in (400, 403, 422):
            return None, 'bad', meta
        return None, 'error', meta
    finally:
        await resp.release()

def _gen_vip_permutations(handle: str) -> List[str]:
    """VIP/personal handle permutations — tighter set (no brand-jargon
    suffixes like `_inc` or `_support`).
    """
    h = handle.lower().strip()
    bare = h.replace('.', '').replace('_', '')
    raw = [
        h, bare,
        f"{h}1", f"{h}_", f"{h}.real", f"real.{h}",
        h.replace('o', '0'), h.replace('i', '1'),
        f"the.{h}", f"{h}.official",
    ]
    seen: Set[str] = set()
    out: List[str] = []
    for p in raw:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


class HikerVipCompositeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "hiker:vip_composite"

    @property
    def description(self) -> str:
        return (
            "HikerAPI VIP composite — runs HK.1.vip (handle permutations) + "
            "HK.2.vip (topsearch + accounts) for executive / individual handle "
            "impersonation discovery on Instagram."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "full_name": {
                    "type": "string",
                    "description": "Full display name (used as topsearch / accounts query).",
                },
                "handle": {
                    "type": "string",
                    "description": "Canonical IG handle (lowercase, no @).",
                },
                "extra_handles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional handle permutations to check.",
                },
                "brand_monitor_id": {
                    "type": "string",
                    "description": "BrandMonitor id (forwarded to ingestion).",
                },
                "tenantId": {
                    "type": "string",
                    "description": "Tenant id (forwarded to ingestion).",
                },
                "vip_id": {
                    "type": "string",
                    "description": "BrandVip id (forwarded to ingestion).",
                },
            },
            "required": ["full_name", "handle"],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "drp_discovery",
            "phase": 5,
            "domain": ["brand_protection", "social", "vip"],
            "input_type": ["handle", "full_name"],
            "output_type": ["vip_impersonators"],
            "chainable_after": [],
            "chainable_before": ["drp:scoring"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        full_name = (parameters.get('full_name') or '').strip()
        handle = (parameters.get('handle') or '').strip().lstrip('@').lower()
        extra_handles = [
            (h or '').strip().lstrip('@').lower()
            for h in (parameters.get('extra_handles') or [])
        ]

        empty_out: Dict[str, Any] = {
            "findings": [], "total": 0,
            "bucket_counts": {B_LEGIT: 0, B_BRAND_ADJ: 0, B_IMPERSONATOR: 0, B_SQUAT: 0},
            "patterns_run": ["HK.1.vip", "HK.2.vip"],
            "subject": {"full_name": full_name, "handle": handle},
            "estimated_credits": 0,
        }

        if not full_name or not handle:
            return {
                "success": False,
                "error": "full_name_and_handle_required",
                "output": empty_out,
            }

        permutations = _gen_vip_permutations(handle) + extra_handles
        seen: Set[str] = set()
        permutations = [
            p for p in permutations
            if p and not (p in seen or seen.add(p))  # type: ignore[func-returns-value]
        ]
        requested_units = len(permutations) + 2  # +HK.2.vip topsearch + accounts

        try:
            lease = await checkout_provider(
                PROVIDER_KEY, requested_units=requested_units,
            )
        except QuotaExceededError as e:
            logger.warning(f"[HK:vip_composite] Quota exceeded: {e}")
            return {
                "success": False, "error": "quota_exceeded",
                "retryAfter": e.retry_after, "providerKey": PROVIDER_KEY,
                "output": empty_out,
            }
        except IntegrationCredentialsError as e:
            logger.error(f"[HK:vip_composite] No backend lease: {e}")
            return {
                "success": False, "error": "no_credentials",
                "message": "No backend integration configured for HIKER_API.",
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
        findings: List[Dict[str, Any]] = []
        actual_calls = 0
        cache_hits = 0
        any_stale = False
        oldest_fetched_at: Optional[float] = None

        try:
            if is_stub:
                # 2026-05-18 — stub-mode synthesis disabled at production
                # dispatch. Fail loud rather than fabricate VIP findings.
                logger.error(
                    "[%s] stub API key detected; refusing to synthesize "
                    "fake HikerAPI VIP-composite findings.", self.name,
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
                        'HIKER_API integration is using a stub API key. '
                        'Synthetic fixtures are disabled. Provision a real key.'
                    ),
                    'providerKey': PROVIDER_KEY,
                    'output': empty_out,
                }
            findings, actual_calls, cache_hits, any_stale, oldest_fetched_at = (
                await self._run_scan(
                    api_key, full_name, handle, permutations,
                    base_url=base_url, timeout_seconds=timeout_seconds,
                    tenant_id=tenant_id, base_ttl=base_ttl,
                    ns_ttls=ns_ttls, stale_grace=stale_grace,
                )
            )
            success = True
        except Exception as e:
            error_code = type(e).__name__
            logger.warning(f"[HK:vip_composite] Upstream call failed: {e}")
        finally:
            agg_cache_hit = bool(actual_calls and cache_hits == actual_calls and not any_stale)
            if is_stub:
                eff_units: int = 0
                rec_cache_hit: Optional[bool] = None
                rec_cache_stale: Optional[bool] = None
            elif agg_cache_hit:
                eff_units = 0
                rec_cache_hit = True
                rec_cache_stale = False
            else:
                eff_units = max(actual_calls - cache_hits, 1) if actual_calls else 1
                rec_cache_hit = False
                rec_cache_stale = any_stale or None
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=eff_units, success=success, error_code=error_code,
                cache_hit=rec_cache_hit, cache_stale=rec_cache_stale,
            )

        bucket_counts = {B_LEGIT: 0, B_BRAND_ADJ: 0, B_IMPERSONATOR: 0, B_SQUAT: 0}
        for f in findings:
            b = f.get('bucket')
            if b in bucket_counts:
                bucket_counts[b] += 1

        meta_out: Dict[str, Any] = {
            'cacheHit': bool(actual_calls and cache_hits == actual_calls and not any_stale),
            'cacheStale': any_stale,
        }
        if oldest_fetched_at is not None:
            meta_out['fetchedAt'] = (
                datetime.fromtimestamp(oldest_fetched_at, tz=timezone.utc)
                .isoformat()
                .replace('+00:00', 'Z')
            )

        return {
            "success": success,
            "output": {
                "findings": findings,
                "total": len(findings),
                "bucket_counts": bucket_counts,
                "patterns_run": ["HK.1.vip", "HK.2.vip"],
                "subject": {"full_name": full_name, "handle": handle},
                "estimated_credits": actual_calls if not is_stub else 0,
                "_meta": meta_out,
            },
            **({"error": error_code} if not success and error_code else {}),
        }

    async def _run_scan(
        self, api_key: str, full_name: str, handle: str,
        permutations: List[str],
        *, base_url: str, timeout_seconds: float,
        tenant_id: Optional[str], base_ttl: Optional[int],
        ns_ttls: Dict[str, int], stale_grace: Optional[int],
    ) -> Tuple[List[Dict[str, Any]], int, int, bool, Optional[float]]:
        headers = {'x-access-key': api_key, 'accept': 'application/json'}
        timeout = aiohttp.ClientTimeout(total=None)
        per_call_timeout = float(timeout_seconds)

        ttl_user = ns_ttls.get(NS_USER) or base_ttl or TTL_USER
        ttl_top = ns_ttls.get(NS_TOPSEARCH) or base_ttl or TTL_TOPSEARCH
        ttl_acct = ns_ttls.get(NS_ACCOUNTS) or base_ttl or TTL_ACCOUNTS

        findings: List[Dict[str, Any]] = []
        call_count = 0
        cache_hits = 0
        any_stale = False
        oldest_fetched_at: Optional[float] = None

        async with aiohttp.ClientSession(timeout=timeout) as session:
            perm_tasks = [
                _safe_get(
                    session, headers, f"{base_url}/v2/user/by/username",
                    {'username': p},
                    provider_label='HikerAPI:user.by.username',
                    timeout_seconds=per_call_timeout,
                    cache_namespace=NS_USER, cache_ttl=ttl_user,
                    stale_grace=stale_grace, tenant_id=tenant_id,
                )
                for p in permutations
            ]
            other_tasks = [
                _safe_get(
                    session, headers, f"{base_url}/v2/fbsearch/topsearch",
                    {'query': full_name},
                    provider_label='HikerAPI:fbsearch.topsearch',
                    timeout_seconds=per_call_timeout,
                    cache_namespace=NS_TOPSEARCH, cache_ttl=ttl_top,
                    stale_grace=stale_grace, tenant_id=tenant_id,
                ),
                _safe_get(
                    session, headers, f"{base_url}/v2/fbsearch/accounts",
                    {'query': full_name},
                    provider_label='HikerAPI:fbsearch.accounts',
                    timeout_seconds=per_call_timeout,
                    cache_namespace=NS_ACCOUNTS, cache_ttl=ttl_acct,
                    stale_grace=stale_grace, tenant_id=tenant_id,
                ),
            ]
            perm_results, other_results = await asyncio.gather(
                asyncio.gather(*perm_tasks, return_exceptions=True),
                asyncio.gather(*other_tasks, return_exceptions=True),
            )

        def _absorb(res: Any) -> Tuple[Optional[Dict[str, Any]], str, Dict[str, Any]]:
            if isinstance(res, BaseException):
                logger.warning(f"[HK:vip_composite] inner task exception: {res}")
                return None, 'error', {'cache_hit': False, 'cache_stale': False, 'fetched_at': None}
            return res  # type: ignore[return-value]

        def _account(meta: Dict[str, Any], status_tag: str) -> None:
            nonlocal call_count, cache_hits, any_stale, oldest_fetched_at
            if status_tag in ('ok', 'not_found', 'bad'):
                call_count += 1
            if meta.get('cache_hit'):
                cache_hits += 1
            if meta.get('cache_stale'):
                any_stale = True
            fa = meta.get('fetched_at')
            if isinstance(fa, (int, float)):
                oldest_fetched_at = (
                    min(oldest_fetched_at, fa) if oldest_fetched_at is not None
                    else float(fa)
                )

        # HK.1.vip — permutation existence checks.
        for username, res in zip(permutations, perm_results):
            data, tag, meta = _absorb(res)
            _account(meta, tag)
            if tag == 'ok' and data:
                acct = _build_account(data)
                bucket, reason, sim = _classify_account(
                    acct, full_name, handle, is_brand=False,
                )
                findings.append({
                    'pattern_id': 'HK.1.vip',
                    'pattern_query': username,
                    'bucket': bucket,
                    'bucket_reason': reason,
                    'similarity': sim,
                    'account': acct,
                })
            elif tag == 'not_found':
                findings.append({
                    'pattern_id': 'HK.1.vip',
                    'pattern_query': username,
                    'bucket': B_SQUAT,
                    'bucket_reason': 'handle does not exist on Instagram — available for registration',
                    'similarity': _similarity(username, handle),
                })

        # HK.2.vip — topsearch users + accounts-search users.
        st_data, st_tag, st_meta = _absorb(other_results[0])
        _account(st_meta, st_tag)
        if st_tag == 'ok' and st_data:
            for it in (st_data.get('list') or []):
                if not isinstance(it, dict):
                    continue
                if not isinstance(it.get('user'), dict):
                    continue  # VIP scan skips hashtags + places
                acct = _build_account(it['user'])
                bucket, reason, sim = _classify_account(
                    acct, full_name, handle, is_brand=False,
                )
                findings.append({
                    'pattern_id': 'HK.2.vip', 'pattern_query': full_name,
                    'bucket': bucket, 'bucket_reason': reason,
                    'similarity': sim, 'account': acct,
                })

        ac_data, ac_tag, ac_meta = _absorb(other_results[1])
        _account(ac_meta, ac_tag)
        if ac_tag == 'ok' and ac_data:
            for u in (ac_data.get('users') or []):
                if not isinstance(u, dict):
                    continue
                acct = _build_account(u)
                bucket, reason, sim = _classify_account(
                    acct, full_name, handle, is_brand=False,
                )
                findings.append({
                    'pattern_id': 'HK.2.vip', 'pattern_query': full_name,
                    'bucket': bucket, 'bucket_reason': reason,
                    'similarity': sim, 'account': acct,
                })

        return findings, call_count, cache_hits, any_stale, oldest_fetched_at
