"""HikerAPI Brand Composite Tool — DRP P0+P1 migration Phase 5b.

Implements `hiker:brand_composite`. Runs the four validated brand-side
DRP patterns in parallel:

  HK.1 — handle-permutation existence check (~10 calls). 404s become
         squat_candidate findings (handle is available for registration).
  HK.2 — fbsearch.topsearch + fbsearch.accounts on brand name (2 calls).
  HK.3 — hashtag.info + hashtag.top + hashtag.recent for `#brand` (3 calls).
  HK.4 — fbsearch.places for brand (1 call, post-filtered by similarity).

Total budget: ~15–17 calls. HikerAPI bills 1 credit per call including
404s. A single permutation 404 / 403 (private account) MUST NOT poison
the gather — those are tracked individually inside `_safe_get` and
absorbed.

Output ships `findings[]` only — Phase 4 Decision 5 made this the SSOT
for Phase 5c ingestion (no back-projected `accounts[]`). `permutations[]`
is a flat convenience array for the FE permutation badge.
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

# Cache namespaces — must match Phase 5a `drp-vendor-requirements.ts` keys.
NS_USER = 'HikerAPI:user.by.username'
NS_TOPSEARCH = 'HikerAPI:fbsearch.topsearch'
NS_ACCOUNTS = 'HikerAPI:fbsearch.accounts'
NS_HASHTAG_INFO = 'HikerAPI:hashtag.info'
NS_HASHTAG_TOP = 'HikerAPI:hashtag.top'
NS_HASHTAG_RECENT = 'HikerAPI:hashtag.recent'
NS_PLACES = 'HikerAPI:fbsearch.places'

TTL_USER = 3600
TTL_TOPSEARCH = 1800
TTL_ACCOUNTS = 300
TTL_HASHTAG_INFO = 21600
TTL_HASHTAG_TOP = 1800
TTL_HASHTAG_RECENT = 600
TTL_PLACES = 86400

# Bucket constants imported from lib.wrapper_helpers above; re-exported here
# implicitly via the `from … import B_*` line for use in this module.


def _gen_brand_permutations(brand: str, brand_handle: str) -> List[str]:
    """Common brand-impersonator handle patterns. ~80% recall on real
    squatter shapes per Phase 4 SMM playbook §2 at ~12-call budget.
    """
    h = brand_handle.lower().strip()
    raw = [
        h, f"{h}1", f"{h}_", f"{h}_official", f"{h}official",
        f"the{h}", f"real{h}",
        h.replace('o', '0'), h.replace('i', '1'),
        f"{h}_inc", f"{h}_support", f"{h}_help",
    ]
    # Dedupe preserving order.
    seen: Set[str] = set()
    out: List[str] = []
    for p in raw:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _build_hashtag(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'name': str(_first(raw, 'name') or ''),
        'media_count': _first(raw, 'media_count'),
    }


def _build_place(raw: Dict[str, Any]) -> Dict[str, Any]:
    inner = raw.get('location') if isinstance(raw.get('location'), dict) else (
        raw.get('place') if isinstance(raw.get('place'), dict) else raw
    )
    return {
        'name': str(_first(inner, 'name') or ''),
        'place_id': str(_first(inner, 'pk', 'id', 'facebook_places_id') or ''),
    }


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
    """Returns `(data, status_tag, meta)`. `status_tag` is:
      - 'ok'         on 200 (data is the parsed dict)
      - 'not_found'  on 404
      - 'bad'        on 400/403 (private account, bad params)
      - 'error'      on 5xx (after upstream_request retries)
    `data` is None on every non-'ok'.
    """
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


class HikerBrandCompositeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "hiker:brand_composite"

    @property
    def description(self) -> str:
        return (
            "HikerAPI brand composite — runs HK.1 (handle permutations) + "
            "HK.2 (topsearch + accounts) + HK.3 (hashtag info/top/recent) + "
            "HK.4 (places) in parallel for Instagram brand impersonation discovery."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "brand": {
                    "type": "string",
                    "description": "Brand name (used for similarity + search queries).",
                },
                "brand_handle": {
                    "type": "string",
                    "description": "Canonical IG handle (lowercase, no @). Defaults to lowercased `brand`.",
                },
                "hashtag": {
                    "type": "string",
                    "description": "Hashtag to scan (without `#`). Defaults to lowercased `brand`.",
                },
                "extra_handles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional handle permutations to check.",
                },
                "benignTokens": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Per-monitor list of benign common words that collide "
                        "with the brand on raw string ratio (e.g. 'acerta'). "
                        "Down-ranks coincidental-word matches lacking any "
                        "corroborating brand signal from impersonator to "
                        "brand_adjacent."
                    ),
                },
                "brand_monitor_id": {
                    "type": "string",
                    "description": "BrandMonitor id (forwarded to ingestion).",
                },
                "tenantId": {
                    "type": "string",
                    "description": "Tenant id (forwarded to ingestion).",
                },
            },
            "required": ["brand"],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "drp_discovery",
            "phase": 5,
            "domain": ["brand_protection", "social"],
            "input_type": ["brand_name"],
            "output_type": ["impersonators", "squat_candidates"],
            "chainable_after": [],
            "chainable_before": ["drp:scoring"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        brand = (parameters.get('brand') or '').strip()
        brand_handle = (
            (parameters.get('brand_handle') or brand).strip().lstrip('@').lower()
        )
        hashtag = (
            (parameters.get('hashtag') or brand).strip().lstrip('#').lower()
        )
        extra_handles = [
            (h or '').strip().lstrip('@').lower()
            for h in (parameters.get('extra_handles') or [])
        ]
        benign_tokens = [
            str(t).strip().lower()
            for t in (parameters.get('benignTokens') or [])
            if t and str(t).strip()
        ]

        empty_out: Dict[str, Any] = {
            "findings": [], "permutations": [], "total": 0,
            "bucket_counts": {B_LEGIT: 0, B_BRAND_ADJ: 0, B_IMPERSONATOR: 0, B_SQUAT: 0},
            "patterns_run": ["HK.1", "HK.2", "HK.3", "HK.4"],
            "subject": {"brand": brand, "brand_handle": brand_handle, "hashtag": hashtag},
            "estimated_credits": 0,
        }

        if not brand:
            return {"success": False, "error": "brand_required", "output": empty_out}

        # Reserve a worst-case budget. HK.1 ~12 + HK.2 ~2 + HK.3 ~3 + HK.4 ~1 = ~18.
        permutations = _gen_brand_permutations(brand, brand_handle) + extra_handles
        # Dedupe preserving order.
        seen: Set[str] = set()
        permutations = [
            p for p in permutations
            if p and not (p in seen or seen.add(p))  # type: ignore[func-returns-value]
        ]
        requested_units = len(permutations) + 6  # +HK.2/3/4 ~6 calls

        try:
            lease = await checkout_provider(
                PROVIDER_KEY, requested_units=requested_units,
            )
        except QuotaExceededError as e:
            logger.warning(f"[HK:brand_composite] Quota exceeded: {e}")
            return {
                "success": False, "error": "quota_exceeded",
                "retryAfter": e.retry_after, "providerKey": PROVIDER_KEY,
                "output": empty_out,
            }
        except IntegrationCredentialsError as e:
            logger.error(f"[HK:brand_composite] No backend lease: {e}")
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
                # dispatch. Fail loud rather than fabricate HK.1–4 findings.
                logger.error(
                    "[%s] stub API key detected; refusing to synthesize "
                    "fake HikerAPI brand-composite findings.", self.name,
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
                    api_key, brand, brand_handle, hashtag,
                    permutations, benign_tokens,
                    base_url=base_url, timeout_seconds=timeout_seconds,
                    tenant_id=tenant_id, base_ttl=base_ttl,
                    ns_ttls=ns_ttls, stale_grace=stale_grace,
                )
            )
            success = True
        except Exception as e:
            error_code = type(e).__name__
            logger.warning(f"[HK:brand_composite] Upstream call failed: {e}")
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
                # HikerAPI bills per call including 404; bill the non-cached
                # call count so the cache_hit attribution is accurate.
                eff_units = max(actual_calls - cache_hits, 1) if actual_calls else 1
                rec_cache_hit = False
                rec_cache_stale = any_stale or None
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=eff_units, success=success, error_code=error_code,
                cache_hit=rec_cache_hit, cache_stale=rec_cache_stale,
            )

        # Build flat permutations[] for FE convenience.
        permutations_out: List[Dict[str, Any]] = []
        for f in findings:
            if f.get('pattern_id') != 'HK.1':
                continue
            acct = f.get('account') or {}
            permutations_out.append({
                'handle': f.get('pattern_query') or acct.get('handle') or '',
                'similarity': f.get('similarity') or 0.0,
                'follower_count': acct.get('follower_count'),
                'is_verified': bool(acct.get('is_verified')) if acct else False,
                'bucket': f.get('bucket'),
            })

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
                "permutations": permutations_out,
                "total": len(findings),
                "bucket_counts": bucket_counts,
                "patterns_run": ["HK.1", "HK.2", "HK.3", "HK.4"],
                "subject": {"brand": brand, "brand_handle": brand_handle, "hashtag": hashtag},
                "estimated_credits": actual_calls if not is_stub else 0,
                "_meta": meta_out,
            },
            **({"error": error_code} if not success and error_code else {}),
        }

    async def _run_scan(
        self, api_key: str, brand: str, brand_handle: str, hashtag: str,
        permutations: List[str], benign_tokens: List[str],
        *, base_url: str, timeout_seconds: float,
        tenant_id: Optional[str], base_ttl: Optional[int],
        ns_ttls: Dict[str, int], stale_grace: Optional[int],
    ) -> Tuple[List[Dict[str, Any]], int, int, bool, Optional[float]]:
        headers = {'x-access-key': api_key, 'accept': 'application/json'}
        timeout = aiohttp.ClientTimeout(total=None)
        per_call_timeout = float(timeout_seconds)

        # TTL resolution.
        ttl_user = ns_ttls.get(NS_USER) or base_ttl or TTL_USER
        ttl_top = ns_ttls.get(NS_TOPSEARCH) or base_ttl or TTL_TOPSEARCH
        ttl_acct = ns_ttls.get(NS_ACCOUNTS) or base_ttl or TTL_ACCOUNTS
        ttl_hinfo = ns_ttls.get(NS_HASHTAG_INFO) or base_ttl or TTL_HASHTAG_INFO
        ttl_htop = ns_ttls.get(NS_HASHTAG_TOP) or base_ttl or TTL_HASHTAG_TOP
        ttl_hrec = ns_ttls.get(NS_HASHTAG_RECENT) or base_ttl or TTL_HASHTAG_RECENT
        ttl_places = ns_ttls.get(NS_PLACES) or base_ttl or TTL_PLACES

        findings: List[Dict[str, Any]] = []
        call_count = 0
        cache_hits = 0
        any_stale = False
        oldest_fetched_at: Optional[float] = None

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Fire HK.1 permutation tasks + HK.2/3/4 in parallel.
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
            other_specs = [
                ('search_top', f"{base_url}/v2/fbsearch/topsearch",
                 {'query': brand}, 'HikerAPI:fbsearch.topsearch',
                 NS_TOPSEARCH, ttl_top),
                ('search_accounts', f"{base_url}/v2/fbsearch/accounts",
                 {'query': brand}, 'HikerAPI:fbsearch.accounts',
                 NS_ACCOUNTS, ttl_acct),
                ('hashtag_info', f"{base_url}/v1/hashtag/by/name",
                 {'name': hashtag}, 'HikerAPI:hashtag.info',
                 NS_HASHTAG_INFO, ttl_hinfo),
                ('hashtag_top', f"{base_url}/v1/hashtag/medias/top/chunk",
                 {'name': hashtag}, 'HikerAPI:hashtag.top',
                 NS_HASHTAG_TOP, ttl_htop),
                ('hashtag_recent', f"{base_url}/v2/hashtag/medias/recent",
                 {'name': hashtag}, 'HikerAPI:hashtag.recent',
                 NS_HASHTAG_RECENT, ttl_hrec),
                ('places', f"{base_url}/v2/fbsearch/places",
                 {'query': brand}, 'HikerAPI:fbsearch.places',
                 NS_PLACES, ttl_places),
            ]
            other_tasks = [
                _safe_get(
                    session, headers, url, params,
                    provider_label=label,
                    timeout_seconds=per_call_timeout,
                    cache_namespace=ns, cache_ttl=ttl,
                    stale_grace=stale_grace, tenant_id=tenant_id,
                )
                for _, url, params, label, ns, ttl in other_specs
            ]
            perm_results, other_results = await asyncio.gather(
                asyncio.gather(*perm_tasks, return_exceptions=True),
                asyncio.gather(*other_tasks, return_exceptions=True),
            )

        def _absorb(res: Any) -> Tuple[Optional[Dict[str, Any]], str, Dict[str, Any]]:
            if isinstance(res, BaseException):
                logger.warning(f"[HK:brand_composite] inner task exception: {res}")
                return None, 'error', {'cache_hit': False, 'cache_stale': False, 'fetched_at': None}
            return res  # type: ignore[return-value]

        # Aggregate call accounting helper.
        def _account(meta: Dict[str, Any], status_tag: str) -> None:
            nonlocal call_count, cache_hits, any_stale, oldest_fetched_at
            # Bill every call that hit the network OR cache. Pure 'error' from
            # transport exhaustion before any HTTP exchange does not count.
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

        # HK.1 — permutation existence checks.
        for username, res in zip(permutations, perm_results):
            data, tag, meta = _absorb(res)
            _account(meta, tag)
            if tag == 'ok' and data:
                acct = _build_account(data)
                bucket, reason, sim = _classify_account(
                    acct, brand, brand_handle, is_brand=True,
                    benign_tokens=benign_tokens,
                )
                findings.append({
                    'pattern_id': 'HK.1',
                    'pattern_query': username,
                    'bucket': bucket,
                    'bucket_reason': reason,
                    'similarity': sim,
                    'handleExists': True,
                    'account': acct,
                })
            elif tag == 'not_found':
                # WP-5: a nonexistent handle is a squat CANDIDATE (available
                # for defensive registration), NOT a live impersonation.
                # `handleExists:false` routes ingestion to an INFO/defensive
                # bucket instead of SOCIAL_IMPERSONATION.
                findings.append({
                    'pattern_id': 'HK.1',
                    'pattern_query': username,
                    'bucket': B_SQUAT,
                    'bucket_reason': 'handle does not exist on Instagram — available for defensive registration',
                    'similarity': _similarity(username, brand_handle),
                    'handleExists': False,
                })
            # 'bad' / 'error' are silently skipped (logged in _safe_get)

        # HK.2 — topsearch + accounts.
        st_data, st_tag, st_meta = _absorb(other_results[0])
        _account(st_meta, st_tag)
        if st_tag == 'ok' and st_data:
            for it in (st_data.get('list') or []):
                if not isinstance(it, dict):
                    continue
                if isinstance(it.get('user'), dict):
                    acct = _build_account(it['user'])
                    bucket, reason, sim = _classify_account(
                        acct, brand, brand_handle, is_brand=True,
                        benign_tokens=benign_tokens,
                    )
                    findings.append({
                        'pattern_id': 'HK.2', 'pattern_query': brand,
                        'bucket': bucket, 'bucket_reason': reason,
                        'similarity': sim, 'account': acct,
                    })
                elif isinstance(it.get('hashtag'), dict):
                    findings.append({
                        'pattern_id': 'HK.2', 'pattern_query': brand,
                        'bucket': B_BRAND_ADJ,
                        'bucket_reason': 'hashtag returned by topsearch',
                        'similarity': 0.0,
                        'hashtag': _build_hashtag(it['hashtag']),
                    })
                elif isinstance(it.get('place'), dict):
                    findings.append({
                        'pattern_id': 'HK.2', 'pattern_query': brand,
                        'bucket': B_BRAND_ADJ,
                        'bucket_reason': 'place returned by topsearch',
                        'similarity': 0.0,
                        'place': _build_place(it['place']),
                    })

        ac_data, ac_tag, ac_meta = _absorb(other_results[1])
        _account(ac_meta, ac_tag)
        if ac_tag == 'ok' and ac_data:
            for u in (ac_data.get('users') or []):
                if not isinstance(u, dict):
                    continue
                acct = _build_account(u)
                bucket, reason, sim = _classify_account(
                    acct, brand, brand_handle, is_brand=True,
                    benign_tokens=benign_tokens,
                )
                findings.append({
                    'pattern_id': 'HK.2', 'pattern_query': brand,
                    'bucket': bucket, 'bucket_reason': reason,
                    'similarity': sim, 'account': acct,
                })

        # HK.3 — hashtag info + top + recent posts.
        hi_data, hi_tag, hi_meta = _absorb(other_results[2])
        _account(hi_meta, hi_tag)
        if hi_tag == 'ok' and hi_data:
            ht = _build_hashtag(hi_data)
            findings.append({
                'pattern_id': 'HK.3',
                'pattern_query': hashtag,
                'bucket': B_BRAND_ADJ,
                'bucket_reason': f"#{hashtag} media_count={ht.get('media_count')}",
                'similarity': 0.0,
                'hashtag': ht,
            })
        for idx in (3, 4):  # hashtag_top, hashtag_recent
            data, tag, meta = _absorb(other_results[idx])
            _account(meta, tag)
            if tag != 'ok' or not data:
                continue
            posts_raw = self._decode_hashtag_chunk(data)
            for p in posts_raw:
                if not isinstance(p, dict):
                    continue
                user_raw = p.get('user') if isinstance(p.get('user'), dict) else None
                if user_raw:
                    acct = _build_account(user_raw)
                    bucket, reason, sim = _classify_account(
                        acct, brand, brand_handle, is_brand=True,
                        benign_tokens=benign_tokens,
                    )
                else:
                    acct = None
                    bucket, reason, sim = B_BRAND_ADJ, 'organic hashtag post (no author)', 0.0
                finding: Dict[str, Any] = {
                    'pattern_id': 'HK.3', 'pattern_query': hashtag,
                    'bucket': bucket, 'bucket_reason': reason,
                    'similarity': sim,
                    'post': {
                        'pk': _first(p, 'pk'),
                        'id': _first(p, 'id', 'pk'),
                        'code': _first(p, 'code', 'shortcode'),
                        'caption_text': (
                            _first(p, 'caption_text') or
                            (p.get('caption', {}).get('text')
                             if isinstance(p.get('caption'), dict) else None)
                        ),
                        'like_count': _first(p, 'like_count'),
                        'comment_count': _first(p, 'comment_count'),
                    },
                }
                if acct is not None:
                    finding['account'] = acct
                findings.append(finding)

        # HK.4 — places.
        pl_data, pl_tag, pl_meta = _absorb(other_results[5])
        _account(pl_meta, pl_tag)
        if pl_tag == 'ok' and pl_data:
            for it in (pl_data.get('items') or []):
                if not isinstance(it, dict):
                    continue
                place = _build_place(it)
                sim = _similarity(place.get('name') or '', brand)
                if sim < 0.5:
                    continue
                bucket = B_LEGIT if sim >= 0.9 else B_IMPERSONATOR
                findings.append({
                    'pattern_id': 'HK.4', 'pattern_query': brand,
                    'bucket': bucket,
                    'bucket_reason': f'place-name similarity={sim:.2f}',
                    'similarity': sim,
                    'place': place,
                })

        return findings, call_count, cache_hits, any_stale, oldest_fetched_at

    @staticmethod
    def _decode_hashtag_chunk(raw: Any) -> List[Dict[str, Any]]:
        """`/v1/hashtag/medias/top/chunk` returns `[posts, cursor]`. Other
        endpoints return `{items:[...]}` or `{medias:[...]}`. Normalize.
        """
        if isinstance(raw, list) and len(raw) >= 1:
            posts = raw[0] if isinstance(raw[0], list) else []
            return [p for p in posts if isinstance(p, dict)]
        if isinstance(raw, dict):
            items = raw.get('items') or raw.get('posts') or raw.get('medias') or []
            return [p for p in items if isinstance(p, dict)]
        return []
