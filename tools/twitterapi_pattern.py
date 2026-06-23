"""twitterapi.io Pattern Scan Tool — DRP P0+P1 migration Phase 5b.

Implements `twitterapi:pattern_scan` — driven by `pattern_id` (one of 9
sub-patterns from Phase 4 SMM playbook §4). Each sub-pattern composes a
specific advanced-search query string against twitterapi.io's
`/twitter/tweet/advanced_search` endpoint.

Supported sub-patterns (single-pattern only; composites are caller's job):
  A.1  — brand-mention baseline                (needs brand + handle)
  A.5  — reply-suspicious phrases to handle    (needs handle)
  B.1  — VIP direct threats                    (needs name)
  B.2  — VIP doxxing / PII proximity           (needs name)
  B.5  — VIP impersonation via blue-verified   (needs name)
  C.1  — leak / breach keyword                 (needs brand + handle)
  C.2  — leak via paste-site URL operators     (needs brand + handle)
  D.1  — fake giveaway / lure                  (needs brand + handle)
  D.2  — customer-support impersonation        (needs handle)

Quota: twitterapi.io bills per `estimate_tweet_call(items) = max(15, items*15)`
credits. We estimate `units = max(1, ceil(limit/100))` per pre-flight
reserve (a 50-tweet result is ~1 page; 500 is 5 pages). The actual unit
count reconciled is the number of pages fetched.
"""

from __future__ import annotations

import sys
import os
import math
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

logger = logging.getLogger(__name__)

PROVIDER_KEY = 'TWITTERAPI_IO'
BASE_URL = 'https://api.twitterapi.io'
DEFAULT_TIMEOUT = 60
PAGE_SIZE = 100
STUB_API_KEY = 'sk-dev-stub-twitterapi-io'

CACHE_NAMESPACE = 'twitterapi.io:advanced_search'
DEFAULT_NAMESPACE_TTL = 300  # SMM playbook §3.2 default for tweet_adv_search.

SUPPORTED_PATTERNS = (
    'A.1', 'A.5', 'B.1', 'B.2', 'B.5', 'C.1', 'C.2', 'D.1', 'D.2',
)

# Conditional-required parameter mapping. Validated in execute().
REQUIRES_BRAND_HANDLE: Tuple[str, ...] = ('A.1', 'C.1', 'C.2', 'D.1')
REQUIRES_HANDLE: Tuple[str, ...] = ('A.5', 'D.2')
REQUIRES_NAME: Tuple[str, ...] = ('B.1', 'B.2', 'B.5')


def _exclude_clauses(handles: Optional[List[str]]) -> str:
    if not handles:
        return ''
    return ' ' + ' '.join(f'-from:{h}' for h in handles if h)


def _compose_query(
    pattern_id: str,
    *,
    brand: Optional[str] = None,
    handle: Optional[str] = None,
    name: Optional[str] = None,
    exclude_handle: Optional[List[str]] = None,
    lang: str = 'en',
) -> str:
    """Verbatim copy of SMM `twitter/routers/drp.py` query strings (lines
    87-332). DO NOT change these — they are validated playbook queries.
    """
    if pattern_id == 'A.1':
        return (
            f'({brand} OR @{handle} OR #{brand}) '
            f'-from:{handle} -filter:retweets lang:{lang}'
        )
    if pattern_id == 'A.5':
        return (
            f'to:{handle} -from:{handle} '
            f'("DM us" OR "DM me" OR "send a DM" OR "verify" OR "secure your account" '
            f'OR "support team" OR "help center" OR url:t.me OR url:wa.me)'
        )
    if pattern_id == 'B.1':
        return (
            f'"{name}" '
            f'(kill OR shoot OR murder OR "deserves to die" OR assassinate OR rape OR lynch) '
            f'-filter:retweets' + _exclude_clauses(exclude_handle)
        )
    if pattern_id == 'B.2':
        return (
            f'"{name}" '
            f'(address OR home OR house OR lives OR "lives at" OR neighborhood OR '
            f'"phone number" OR doxx OR dox OR doxxed OR SSN) '
            f'-filter:retweets -filter:news' + _exclude_clauses(exclude_handle)
        )
    if pattern_id == 'B.5':
        return (
            f'"{name}" (CEO OR founder OR "Chief Executive")'
            + _exclude_clauses(exclude_handle)
            + ' filter:blue_verified'
        )
    if pattern_id == 'C.1':
        return (
            f'({brand} OR @{handle}) '
            f'(breach OR breached OR "data breach" OR leaked OR dump OR pwned OR hacked OR "0day") '
            f'-filter:retweets lang:{lang}'
        )
    if pattern_id == 'C.2':
        return (
            f'({brand} OR @{handle}) '
            f'(url:pastebin.com OR url:rentry.co OR url:ghostbin OR url:doxbin '
            f'OR url:justpaste.it OR url:dpaste.com OR url:hastebin.com) -filter:retweets'
        )
    if pattern_id == 'D.1':
        return (
            f'({brand} OR @{handle}) '
            f'(free OR giveaway OR "claim now" OR "limited time" OR "first 1000" '
            f'OR airdrop OR "100x" OR double) -from:{handle} -filter:retweets lang:{lang}'
        )
    if pattern_id == 'D.2':
        return (
            f'to:{handle} -from:{handle} '
            f'("DM us" OR "DM me" OR "DM our team" OR "verify" OR "secure your account" '
            f'OR "chat support" OR "WhatsApp" OR "Telegram" OR "+1" OR url:t.me OR url:wa.me)'
        )
    raise ValueError(f'unknown pattern_id={pattern_id!r}')


def _tweet_id_of(t: Any) -> Optional[str]:
    if not isinstance(t, dict):
        return None
    tid = t.get('id') or t.get('tweet_id') or t.get('id_str')
    if tid is None:
        return None
    return str(tid)


class TwitterApiPatternScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "twitterapi:pattern_scan"

    @property
    def description(self) -> str:
        return (
            "twitterapi.io advanced-search runner driven by a single "
            "sub-pattern id (one of A.1, A.5, B.1, B.2, B.5, C.1, C.2, D.1, D.2). "
            "Each pattern composes a validated DRP playbook query."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "pattern_id": {
                    "type": "string",
                    "enum": list(SUPPORTED_PATTERNS),
                    "description": "DRP playbook sub-pattern id.",
                },
                "brand": {
                    "type": "string",
                    "description": "Brand keyword (required for A.1, C.1, C.2, D.1).",
                },
                "handle": {
                    "type": "string",
                    "description": "Brand's @-handle, no @ (required for A.1, A.5, C.1, C.2, D.1, D.2).",
                },
                "name": {
                    "type": "string",
                    "description": "VIP full name (required for B.1, B.2, B.5).",
                },
                "exclude_handle": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Handles to exclude (VIP patterns commonly exclude VIP + brand).",
                },
                "lang": {
                    "type": "string",
                    "description": "Language filter for keyword patterns (default 'en').",
                    "default": "en",
                },
                "since": {
                    "type": "integer",
                    "description": "Epoch seconds; only tweets after this time.",
                },
                "until": {
                    "type": "integer",
                    "description": "Epoch seconds; only tweets before this time.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max tweets to return (default 50, max 500).",
                    "default": 50,
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
                    "description": (
                        "BrandVip id (forwarded to ingestion). Set for the "
                        "VIP-targeted B.* patterns so each finding can be "
                        "attributed to the specific executive."
                    ),
                },
            },
            "required": ["pattern_id"],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "drp_discovery",
            "phase": 5,
            "domain": ["brand_protection", "social"],
            "input_type": ["pattern_id", "brand_or_name"],
            "output_type": ["tweets", "findings"],
            "chainable_after": [],
            "chainable_before": ["drp:scoring"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        pattern_id = (parameters.get('pattern_id') or '').strip()
        brand = (parameters.get('brand') or '').strip() or None
        handle = (parameters.get('handle') or '').strip().lstrip('@') or None
        name = (parameters.get('name') or '').strip() or None
        exclude_handle_raw = parameters.get('exclude_handle') or []
        exclude_handle = [
            (h or '').strip().lstrip('@') for h in exclude_handle_raw if h
        ]
        lang = (parameters.get('lang') or 'en').strip() or 'en'
        # VIP attribution provenance: echo an explicit vip_id when the caller
        # supplies it (B.* VIP patterns), and the VIP `name` we already
        # searched for. The backend stamps the run-level vip_id onto
        # VIP_IMPERSONATION findings (and uses the name as a precision-gated
        # resolver fallback), so emitting these at the run level gives precise
        # attribution without per-finding duplication.
        vip_id = (parameters.get('vip_id') or '').strip() or None
        since = parameters.get('since')
        until = parameters.get('until')
        limit = int(parameters.get('limit', 50) or 50)
        limit = max(1, min(limit, 500))

        empty_subject: Dict[str, Any] = {}
        if brand is not None:
            empty_subject['brand'] = brand
        if handle is not None:
            empty_subject['handle'] = handle
        if name is not None:
            empty_subject['name'] = name
        if exclude_handle:
            empty_subject['exclude_handle'] = exclude_handle
        if lang:
            empty_subject['lang'] = lang

        empty_out: Dict[str, Any] = {
            "findings": [], "tweets": [], "patterns_run": [],
            "total": 0, "subject": empty_subject,
            "window": {"since": since, "until": until},
        }

        # Conditional-required validation.
        if pattern_id not in SUPPORTED_PATTERNS:
            return {
                "success": False,
                "error": "invalid_pattern_id",
                "message": (
                    f"pattern_id must be one of {SUPPORTED_PATTERNS}; got {pattern_id!r}"
                ),
                "output": empty_out,
            }
        if pattern_id in REQUIRES_BRAND_HANDLE and (not brand or not handle):
            return {
                "success": False,
                "error": "brand_and_handle_required",
                "message": f"pattern {pattern_id} requires both `brand` and `handle`",
                "output": empty_out,
            }
        if pattern_id in REQUIRES_HANDLE and not handle:
            return {
                "success": False,
                "error": "handle_required",
                "message": f"pattern {pattern_id} requires `handle`",
                "output": empty_out,
            }
        if pattern_id in REQUIRES_NAME and not name:
            return {
                "success": False,
                "error": "name_required",
                "message": f"pattern {pattern_id} requires `name`",
                "output": empty_out,
            }

        # Compose query; defensive try in case of unforeseen interpolation issue.
        try:
            query = _compose_query(
                pattern_id,
                brand=brand, handle=handle, name=name,
                exclude_handle=exclude_handle, lang=lang,
            )
        except Exception as exc:
            return {
                "success": False,
                "error": "query_compose_failed",
                "message": str(exc)[:200],
                "output": empty_out,
            }

        requested_units = max(1, math.ceil(limit / PAGE_SIZE))

        try:
            lease = await checkout_provider(
                PROVIDER_KEY, requested_units=requested_units,
            )
        except QuotaExceededError as e:
            logger.warning(f"[twitterapi:pattern_scan] Quota exceeded: {e}")
            return {
                "success": False, "error": "quota_exceeded",
                "retryAfter": e.retry_after, "providerKey": PROVIDER_KEY,
                "output": empty_out,
            }
        except IntegrationCredentialsError as e:
            logger.error(f"[twitterapi:pattern_scan] No backend lease: {e}")
            return {
                "success": False, "error": "no_credentials",
                "message": "No backend integration configured for TWITTERAPI_IO.",
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
        tweets: List[Dict[str, Any]] = []
        first_page_meta: Optional[Dict[str, Any]] = None
        total_pages = 0

        try:
            if is_stub:
                # 2026-05-18 — stub-mode synthesis disabled at production
                # dispatch. Fail loud rather than fabricate tweets.
                logger.error(
                    "[%s] stub API key detected; refusing to synthesize "
                    "fake twitterapi.io pattern-scan tweets.", self.name,
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
                        'TWITTERAPI_IO integration is using a stub API key. '
                        'Synthetic fixtures are disabled. Provision a real key.'
                    ),
                    'providerKey': PROVIDER_KEY,
                    'output': empty_out,
                }
            tweets, first_page_meta, total_pages = await self._query(
                api_key, query, since, until, limit,
                base_url=base_url, timeout_seconds=timeout_seconds,
                tenant_id=tenant_id, base_ttl=base_ttl,
                ns_ttls=ns_ttls, stale_grace=stale_grace,
            )
            success = True
        except Exception as e:
            error_code = type(e).__name__
            logger.warning(f"[twitterapi:pattern_scan] Upstream call failed: {e}")
        finally:
            if is_stub:
                eff_units: int = 0
                rec_cache_hit: Optional[bool] = None
                rec_cache_stale: Optional[bool] = None
            elif (
                first_page_meta is not None
                and first_page_meta.get('cache_hit')
                and not first_page_meta.get('cache_stale')
                and total_pages == 1
            ):
                eff_units = 0
                rec_cache_hit = True
                rec_cache_stale = False
            elif (
                first_page_meta is not None
                and first_page_meta.get('cache_hit')
                and not first_page_meta.get('cache_stale')
            ):
                eff_units = max(total_pages - 1, 0)
                rec_cache_hit = False
                rec_cache_stale = None
            else:
                eff_units = max(total_pages, 1)
                rec_cache_hit = False
                rec_cache_stale = (
                    bool(first_page_meta and first_page_meta.get('cache_stale')) or None
                )
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=eff_units, success=success, error_code=error_code,
                cache_hit=rec_cache_hit, cache_stale=rec_cache_stale,
            )

        # Build findings list with stable per-tweet pattern provenance.
        findings: List[Dict[str, Any]] = []
        seen_tids: set[str] = set()
        for t in tweets:
            tid = _tweet_id_of(t)
            if tid and tid in seen_tids:
                continue
            if tid:
                seen_tids.add(tid)
            finding: Dict[str, Any] = {
                'pattern_id': pattern_id,
                'pattern_query': query,
                'tweet_id': tid or '',
                'tweet': t,
            }
            # NOTE: VIP attribution provenance is echoed ONLY at the run level
            # (`output.vip_id`/`output.vip_name`, set below). The backend
            # ingestion handler reads the run-level fields, not per-finding
            # ones, so we intentionally do NOT stamp vip_id/vip_name onto each
            # finding wrapper — that would be dead data the backend never reads.
            findings.append(finding)

        meta_out: Dict[str, Any] = {
            'cacheHit': bool(
                first_page_meta
                and first_page_meta.get('cache_hit')
                and total_pages == 1
            ),
            'cacheStale': bool(
                first_page_meta and first_page_meta.get('cache_stale')
            ),
        }
        if first_page_meta and first_page_meta.get('fetched_at'):
            meta_out['fetchedAt'] = (
                datetime.fromtimestamp(first_page_meta['fetched_at'], tz=timezone.utc)
                .isoformat()
                .replace('+00:00', 'Z')
            )

        return {
            "success": success,
            "output": {
                "findings": findings,
                "tweets": tweets,
                "patterns_run": [pattern_id],
                "total": len(findings),
                "subject": empty_subject,
                "window": {"since": since, "until": until},
                # Top-level VIP attribution provenance — ingestion reads
                # `output.vip_id`/`output.vip_name` as the run-level fallback
                # (mirrors hiker:vip_composite). Emitted only when known.
                **({"vip_id": vip_id} if vip_id else {}),
                **({"vip_name": name} if name else {}),
                "_meta": meta_out,
            },
            **({"error": error_code} if not success and error_code else {}),
        }

    async def _query(
        self, api_key: str, query: str,
        since: Optional[int], until: Optional[int], limit: int,
        *, base_url: str, timeout_seconds: float,
        tenant_id: Optional[str], base_ttl: Optional[int],
        ns_ttls: Dict[str, int], stale_grace: Optional[int],
    ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]], int]:
        headers = {'X-API-Key': api_key, 'accept': 'application/json'}
        url = f"{base_url}/twitter/tweet/advanced_search"
        base_params: Dict[str, Any] = {
            'query': query,
            'queryType': 'Latest',
        }
        if since is not None:
            base_params['since_time'] = int(since)
        if until is not None:
            base_params['until_time'] = int(until)

        ttl = ns_ttls.get(CACHE_NAMESPACE) or base_ttl or DEFAULT_NAMESPACE_TTL
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)

        collected: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        first_page_meta: Optional[Dict[str, Any]] = None
        total_pages = 0

        async with aiohttp.ClientSession(timeout=timeout) as session:
            while len(collected) < limit:
                page_params = dict(base_params)
                if cursor:
                    page_params['cursor'] = cursor
                is_first_page = cursor is None
                resp, page_meta = await upstream_request(
                    session, 'GET', url,
                    headers=headers, params=page_params,
                    provider_label='twitterapi.io:advanced_search',
                    timeout_seconds=timeout_seconds,
                    cache_namespace=CACHE_NAMESPACE if is_first_page else None,
                    cache_ttl_seconds=ttl if is_first_page else None,
                    stale_grace_seconds=stale_grace if is_first_page else None,
                    tenant_id=tenant_id if is_first_page else None,
                )
                if is_first_page:
                    first_page_meta = page_meta
                total_pages += 1
                try:
                    if resp.status != 200:
                        text = await resp.text()
                        raise RuntimeError(
                            f"twitterapi.io HTTP {resp.status}: {text[:200]}"
                        )
                    data = await resp.json()
                finally:
                    await resp.release()

                if not isinstance(data, dict):
                    break
                page_tweets = data.get('tweets')
                if not isinstance(page_tweets, list):
                    page_tweets = (
                        (data.get('data') or {}).get('tweets')
                        if isinstance(data.get('data'), dict) else None
                    ) or []
                if not page_tweets:
                    break

                collected.extend(
                    t for t in page_tweets if isinstance(t, dict)
                )

                cursor = data.get('next_cursor') or data.get('cursor')
                if not cursor:
                    break

        return collected[:limit], first_page_meta, total_pages
