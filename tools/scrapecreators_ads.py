"""ScrapeCreators Ad Impersonation Tool — DRP P0+P1 migration Phase 5b.

Implements `scrapecreators:ad_impersonation` — the FB Ad Library + LinkedIn
Ad Library 3-bucket classifier. Highest-operational-value DRP composite
per Phase 4 SMM playbook §5 / §7.3: paginates the FB ad library for
`query=brand`, fetches LinkedIn ads twice (`company=brand`, `keyword=brand`),
and classifies each ad into `legit | brand_adjacent | impersonator`
against the caller-supplied allowlist of FB page IDs, link domains, and
LinkedIn company IDs / names.

Endpoints (validated, SMM `scrapecreators/routers/drp.py:213-335`):
  - GET /v1/facebook/adLibrary/search/ads?query=<brand>&cursor=<...>
  - GET /v1/linkedin/ads/search?company=<brand>  (and ?keyword=<brand>)

Per-platform 4xx errors are absorbed so one platform's failure does not
poison the other. 5xx retries via `upstream_request` then propagates.

Quota: ScrapeCreators bills 1 credit per call (including 404). Each FB
pagination page is 1 call; LinkedIn modes are 1 call each. Stub mode
synthesizes 3 ads (1 legit + 1 brand_adjacent + 1 impersonator) and
reconciles units=0.
"""

from __future__ import annotations

import sys
import os
import re
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set
from urllib.parse import urlparse

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
from lib.wrapper_helpers import first as _first, similarity as _similarity

logger = logging.getLogger(__name__)

PROVIDER_KEY = 'SCRAPECREATORS'
BASE_URL = 'https://api.scrapecreators.com'
DEFAULT_TIMEOUT = 30
STUB_API_KEY = 'sk-dev-stub-scrapecreators'

NS_FB_ADS = 'ScrapeCreators:facebook_ads'
NS_LI_ADS = 'ScrapeCreators:linkedin_ads'
DEFAULT_TTL_FB_ADS = 1800
DEFAULT_TTL_LI_ADS = 1800

FB_ADS_PATH = '/v1/facebook/adLibrary/search/ads'
LI_ADS_PATH = '/v1/linkedin/ads/search'


def _coerce_iso(ts: Any) -> Optional[str]:
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


def _domain(url: Optional[str]) -> str:
    if not url:
        return ''
    try:
        host = urlparse(url).netloc.lower()
        if host.startswith('www.'):
            host = host[4:]
        return host
    except Exception:
        return ''


def _build_fb_ad(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a ScrapeCreators FB Ad Library record. Mirrors
    SMM `app/scrapecreators/models.py:fb_ad_record()`."""
    snap = raw.get('snapshot') if isinstance(raw.get('snapshot'), dict) else {}
    body_v = snap.get('body') if isinstance(snap, dict) else None
    body_text = body_v.get('text') if isinstance(body_v, dict) else None

    ad_id = str(_first(raw, 'ad_archive_id', 'id') or '') or None
    advertiser_id = str(_first(snap, 'page_id') or _first(raw, 'page_id') or '') or None
    advertiser_name = _first(snap, 'page_name') or _first(raw, 'page_name')
    link_url = _first(snap, 'link_url')
    advertiser_url = _first(snap, 'page_profile_uri')
    # Collect any preview image URLs from the snapshot. SC returns a list
    # under snapshot.images / snapshot.cards depending on the creative.
    image_urls: List[str] = []
    for k in ('images', 'cards'):
        v = snap.get(k) if isinstance(snap, dict) else None
        if isinstance(v, list):
            for it in v:
                if isinstance(it, dict):
                    u = _first(it, 'resized_image_url', 'original_image_url', 'image_url')
                    if isinstance(u, str) and u:
                        image_urls.append(u)
    return {
        'advertiser_id': advertiser_id,
        'advertiser_name': str(advertiser_name) if advertiser_name else None,
        'advertiser_url': advertiser_url,
        'link_url': link_url,
        'link_domain': _domain(link_url) or None,
        'creative_text': body_text,
        'ad_id': ad_id,
        'image_urls': image_urls,
        'first_seen_at': _coerce_iso(
            _first(raw, 'start_date', 'start_date_string', 'ad_delivery_start_time')
        ),
        'last_seen_at': _coerce_iso(
            _first(raw, 'end_date', 'end_date_string', 'ad_delivery_stop_time')
        ),
    }


def _build_li_ad(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a ScrapeCreators LinkedIn Ad Library record.

    Verified live shape (2026-05-18) — top-level keys:
      id, description, headline, poster, posterTitle, promotedBy, targeting,
      image, video, carouselImages, url, adType, creativeType, advertiser,
      advertiserLinkedinPage, cta, destinationUrl, adDuration, startDate,
      endDate, totalImpressions, impressionsByCountry.
    `advertiser` is a STRING (LI advertiser display name), not a dict.
    """
    # `advertiser` is a string for LI ads; fall back to nested dict only
    # if the vendor ever changes shape.
    advertiser_block = (
        raw.get('advertiser') if isinstance(raw.get('advertiser'), dict) else None
    )
    advertiser_str = (
        raw.get('advertiser') if isinstance(raw.get('advertiser'), str) else None
    )
    advertiser_name = (
        (advertiser_block.get('name') if advertiser_block else None)
        or advertiser_str
        or _first(
            raw,
            'promotedBy',
            'posterTitle',
            'company',
            'companyName',
            'companyDisplayName',
            'advertiserName',
            'advertiserDisplayName',
            'sponsorName',
            'payerName',
        )
    )
    advertiser_id_raw = (
        (advertiser_block.get('id') if advertiser_block else None)
        or _first(raw, 'companyId', 'advertiserId', 'sponsorId')
    )
    # LinkedIn body/copy is `description`; `headline` is a separate short field.
    body = _first(raw, 'description', 'body', 'text', 'content', 'commentary')
    if isinstance(body, dict):
        body = body.get('text', '')
    headline = _first(raw, 'headline', 'title')
    if isinstance(headline, dict):
        headline = headline.get('text', '')
    # If both present, prefer the longer / fuller body but keep headline visible.
    creative_text = body if body else headline
    cta_text_raw = _first(raw, 'cta', 'ctaText', 'callToAction')
    if isinstance(cta_text_raw, dict):
        cta_text_raw = cta_text_raw.get('text') or cta_text_raw.get('label')
    link_url = _first(
        raw, 'destinationUrl', 'landingUrl', 'linkUrl', 'url',
    )
    advertiser_url = _first(
        raw, 'advertiserLinkedinPage', 'companyUrl', 'advertiserUrl', 'promotedByUrl',
    )
    images_raw = raw.get('images') if isinstance(raw.get('images'), list) else []
    if not images_raw and isinstance(raw.get('carouselImages'), list):
        images_raw = raw['carouselImages']
    if not images_raw and isinstance(raw.get('image'), str):
        images_raw = [raw['image']]
    image_urls = [
        i for i in images_raw
        if isinstance(i, str) and i.startswith('http')
    ]
    return {
        'advertiser_id': str(advertiser_id_raw) if advertiser_id_raw is not None else None,
        'advertiser_name': str(advertiser_name) if advertiser_name else None,
        'advertiser_url': str(advertiser_url) if advertiser_url else None,
        'link_url': link_url,
        'link_domain': _domain(link_url) or None,
        'creative_text': str(creative_text) if creative_text else None,
        'headline': str(headline) if headline and headline != body else None,
        'cta_text': str(cta_text_raw) if cta_text_raw else None,
        'ad_id': str(_first(raw, 'id', 'adId') or '') or None,
        'image_urls': image_urls,
        'first_seen_at': _coerce_iso(_first(raw, 'first_seen', 'firstSeen', 'startDate')),
        'last_seen_at': _coerce_iso(_first(raw, 'last_seen', 'lastSeen', 'endDate')),
    }


def _domain_matches_whitelist(dom: str, legit_domains: Set[str]) -> bool:
    """True iff `dom` is in `legit_domains` OR is a subdomain of any entry.

    Real-world ads frequently land on a brand-owned subdomain
    (`trade.questrade.com`, `my.shopify.com`, `careers.airbnb.com`). The
    Repo A spec used exact equality which produced false-positive
    `impersonator` rulings on legit subdomain ads. Suffix-match on a leading
    dot prevents the loose case of `evil-questrade.com` matching
    `questrade.com` while admitting any subdomain of a whitelisted apex.
    """
    if not dom:
        return False
    dom = dom.lower().strip()
    for w in legit_domains:
        w_l = w.lower().strip()
        if not w_l:
            continue
        if dom == w_l or dom.endswith(f'.{w_l}'):
            return True
    return False


def _alnum(s: Optional[str]) -> str:
    """Lowercase + strip non-alphanumerics — robust substring matching that
    ignores spacing/punctuation differences (`Mrs Tutor` vs `mrstutor`)."""
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


def _ad_brand_relevance(ad: Dict[str, Any], brand: str) -> Tuple[bool, List[str]]:
    """WP-2 brand-relevance gate.

    A non-whitelisted ad is an *impersonator* only if it actually references
    the monitored brand. Ads surfaced by a loose keyword search that share no
    brand-distinctive signal — advertiser/page name, link domain, or creative
    text — are unrelated advertisers, NOT impersonators. Returning
    `impersonator` for those is the ~90% false-positive dragnet WP-2 removes.

    Returns `(is_relevant, signals)`.
    """
    brand_key = _alnum(brand)
    signals: List[str] = []
    if not brand_key:
        return False, signals
    name = ad.get('advertiser_name') or ''
    dom = ad.get('link_domain') or ''
    text = ad.get('creative_text') or ''
    name_key = _alnum(name)
    if name_key and (brand_key in name_key or _similarity(name, brand) >= 0.8):
        signals.append('advertiser_name_brand_match')
    if brand_key in _alnum(dom):
        signals.append('link_domain_brand_match')
    if brand_key in _alnum(text):
        signals.append('creative_text_brand_match')
    return (len(signals) > 0, signals)


def _classify_fb(
    ad: Dict[str, Any], legit_page_ids: Set[str], legit_domains: Set[str],
    brand: str,
) -> Tuple[str, str, List[str]]:
    """3-bucket classifier — page_id authoritative, subdomain-aware.

    2026-05-18 — diverges from Repo A SMM playbook §5 semantics in two ways:
    (1) `page_id` match → `legit` REGARDLESS of `link_url` domain. Real Meta
        ads almost always route through tracking redirects (doubleclick,
        googleadservices, hubspot) or a brand-owned subdomain whose suffix
        differs from the apex. Treating page_id as authoritative trusts
        Meta's own page identity over the brittle redirect-domain signal.
    (2) Domain matching uses subdomain-aware suffix logic via
        `_domain_matches_whitelist`, NOT raw string equality. A whitelist
        of `questrade.com` admits `trade.questrade.com`, `www.questrade.com`,
        etc., but not `evil-questrade.com` or `questrade.scam.tld`.

    WP-2 (2026-06-11): a non-whitelisted ad only escalates to `impersonator`
    when it carries a brand-relevance signal (`_ad_brand_relevance`).
    Otherwise it is an unrecognized advertiser surfaced by the brand keyword
    search and is bucketed `brand_adjacent` (low-severity mention), never
    impersonator — this removes the keyword-search false-positive dragnet.

    Order matters — return on first match.
    """
    pid = ad.get('advertiser_id') or ''
    dom = ad.get('link_domain') or ''
    pid_match = pid in legit_page_ids if pid else False
    domain_match = _domain_matches_whitelist(dom, legit_domains)

    evidence: List[str] = []
    if pid:
        evidence.append(f"page_id={pid}")
    if dom:
        evidence.append(f"link_domain={dom}")

    if pid_match:
        # page_id authoritative — Meta has verified this page identity.
        return (
            'legit',
            f"page_id={pid} matches whitelist (Meta page-identity authoritative)",
            evidence + ['page_id_whitelisted'],
        )
    if domain_match:
        return (
            'brand_adjacent',
            f"link_url domain `{dom}` is whitelisted but page_id `{pid}` is not",
            evidence + ['domain_whitelisted', 'page_id_not_whitelisted'],
        )

    is_relevant, relevance_signals = _ad_brand_relevance(ad, brand)
    if not is_relevant:
        # No brand-distinctive signal — unrelated advertiser, not an
        # impersonator. Low-severity mention for analyst awareness only.
        return (
            'brand_adjacent',
            (
                f"page_id `{pid or '(none)'}` and link_url domain "
                f"`{dom or '(none)'}` not whitelisted, but ad carries NO "
                f"brand-relevance signal (advertiser name / link domain / "
                f"creative text do not reference the brand) — unrecognized "
                f"advertiser surfaced by keyword search, not impersonation"
            ),
            evidence + ['no_brand_relevance', 'page_id_not_whitelisted'],
        )
    return (
        'impersonator',
        (
            f"page_id `{pid}` not in whitelist AND link_url domain "
            f"`{dom or '(none)'}` not in whitelist (subdomain-aware), AND ad "
            f"references the brand ({', '.join(relevance_signals)})"
        ),
        evidence
        + ['page_id_not_whitelisted', 'domain_not_whitelisted']
        + relevance_signals,
    )


def _classify_li(
    ad: Dict[str, Any],
    legit_company_ids: Set[str],
    legit_company_names: Set[str],
) -> Tuple[str, str, List[str]]:
    cid = ad.get('advertiser_id') or ''
    name = (ad.get('advertiser_name') or '').lower()
    evidence: List[str] = []
    if cid:
        evidence.append(f"company_id={cid}")
    if name:
        evidence.append(f"advertiser_name={name}")

    if cid and cid in legit_company_ids:
        return (
            'legit',
            f"company_id={cid} matches whitelist",
            evidence + ['company_id_whitelisted'],
        )
    if any(n.lower() in name for n in legit_company_names if n):
        return (
            'legit',
            "advertiser name contains legit company token",
            evidence + ['advertiser_name_whitelisted'],
        )
    return (
        'brand_adjacent',
        "advertiser is not whitelisted; manual review for impersonator vs competitor",
        evidence + ['advertiser_not_whitelisted'],
    )


class ScrapeCreatorsAdImpersonationTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "scrapecreators:ad_impersonation"

    @property
    def description(self) -> str:
        return (
            "Sweep Facebook + LinkedIn ad libraries for impersonation: paginates "
            "FB Ad Library by brand query, fetches LinkedIn ads by company+keyword, "
            "and classifies each as legit / brand_adjacent / impersonator."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "brand": {
                    "type": "string",
                    "description": "Brand keyword used for FB query and LinkedIn company/keyword search.",
                },
                "fb_legit_page_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowlist of Facebook Page IDs known to belong to the brand.",
                },
                "legit_domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowlist of link-URL domains owned by the brand.",
                },
                "li_legit_company_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowlist of LinkedIn company IDs known to belong to the brand.",
                },
                "li_legit_company_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowlist of LinkedIn advertiser-name substrings (case-insensitive).",
                },
                "fb_max_pages": {
                    "type": "integer",
                    "description": "Max FB Ad Library pages to paginate (default 5, max 8).",
                    "default": 5,
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
            "domain": ["brand_protection", "ads"],
            "input_type": ["brand_name"],
            "output_type": ["ad_impersonators"],
            "chainable_after": [],
            "chainable_before": ["drp:scoring"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        brand = (parameters.get('brand') or '').strip()
        fb_legit_pages: Set[str] = set(
            str(p) for p in (parameters.get('fb_legit_page_ids') or [])
        )
        legit_domains: Set[str] = set(
            (d or '').lower().lstrip('.').lstrip('www.')
            for d in (parameters.get('legit_domains') or [])
        )
        li_legit_ids: Set[str] = set(
            str(c) for c in (parameters.get('li_legit_company_ids') or [])
        )
        li_legit_names: Set[str] = set(
            n for n in (parameters.get('li_legit_company_names') or []) if n
        )
        fb_max_pages = max(1, min(int(parameters.get('fb_max_pages', 5) or 5), 8))

        empty_out: Dict[str, Any] = {
            "items": [], "total": 0, "brand": brand,
            "bucket_counts": {"legit": 0, "brand_adjacent": 0, "impersonator": 0},
        }

        if not brand:
            return {"success": False, "error": "brand_required", "output": empty_out}

        # Pre-flight reserve: assume worst-case pagination depth + 2 LinkedIn modes.
        requested_units = fb_max_pages + 2

        try:
            lease = await checkout_provider(
                PROVIDER_KEY, requested_units=requested_units,
            )
        except QuotaExceededError as e:
            logger.warning(f"[SC:ad_impersonation] Quota exceeded: {e}")
            return {
                "success": False, "error": "quota_exceeded",
                "retryAfter": e.retry_after, "providerKey": PROVIDER_KEY,
                "output": empty_out,
            }
        except IntegrationCredentialsError as e:
            logger.error(f"[SC:ad_impersonation] No backend lease: {e}")
            return {
                "success": False, "error": "no_credentials",
                "message": "No backend integration configured for SCRAPECREATORS.",
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
        actual_calls = 0
        agg_cache_hit = False
        agg_cache_stale = False
        oldest_fetched_at: Optional[float] = None

        try:
            if is_stub:
                # 2026-05-18 — stub-mode synthesis is disabled at the
                # production dispatch path. Any tenant configured with the
                # stub API key MUST be re-provisioned with a real key before
                # this tool will run. Fail loudly rather than silently
                # producing fake AD_IMPERSONATION rows.
                logger.error(
                    "[%s] stub API key detected at runtime; refusing to synthesize "
                    "fake ad-library data. Re-provision the SCRAPECREATORS "
                    "integration with a real key.", self.name,
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
                        'Synthetic fixtures are disabled in production '
                        'dispatch. Provision a real ScrapeCreators API key.'
                    ),
                    'providerKey': PROVIDER_KEY,
                    'output': empty_out,
                }
            items, actual_calls, agg_cache_hit, agg_cache_stale, oldest_fetched_at = (
                await self._run_scan(
                    api_key, brand, fb_legit_pages, legit_domains,
                    li_legit_ids, li_legit_names, fb_max_pages,
                    base_url=base_url, timeout_seconds=timeout_seconds,
                    tenant_id=tenant_id, base_ttl=base_ttl,
                    ns_ttls=ns_ttls, stale_grace=stale_grace,
                )
            )
            success = True
        except Exception as e:
            error_code = type(e).__name__
            logger.warning(f"[SC:ad_impersonation] Upstream call failed: {e}")
        finally:
            if is_stub:
                eff_units: int = 0
                rec_cache_hit: Optional[bool] = None
                rec_cache_stale: Optional[bool] = None
            elif agg_cache_hit and not agg_cache_stale:
                eff_units = 0
                rec_cache_hit = True
                rec_cache_stale = False
            else:
                eff_units = max(actual_calls, 1)
                rec_cache_hit = False
                rec_cache_stale = agg_cache_stale or None
            await reconcile_call(
                PROVIDER_KEY, lease_token,
                units=eff_units, success=success, error_code=error_code,
                cache_hit=rec_cache_hit, cache_stale=rec_cache_stale,
            )

        # Aggregate bucket counts for the output envelope.
        bucket_counts = {"legit": 0, "brand_adjacent": 0, "impersonator": 0}
        for it in items:
            b = it.get('bucket')
            if b in bucket_counts:
                bucket_counts[b] += 1

        meta_out: Dict[str, Any] = {
            'cacheHit': agg_cache_hit,
            'cacheStale': agg_cache_stale,
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
                "items": items,
                "total": len(items),
                "brand": brand,
                "bucket_counts": bucket_counts,
                "_meta": meta_out,
            },
            **({"error": error_code} if not success and error_code else {}),
        }

    async def _run_scan(
        self, api_key: str, brand: str,
        fb_legit_pages: Set[str], legit_domains: Set[str],
        li_legit_ids: Set[str], li_legit_names: Set[str],
        fb_max_pages: int,
        *, base_url: str, timeout_seconds: float,
        tenant_id: Optional[str], base_ttl: Optional[int],
        ns_ttls: Dict[str, int], stale_grace: Optional[int],
    ) -> Tuple[List[Dict[str, Any]], int, bool, bool, Optional[float]]:
        headers = {'x-api-key': api_key, 'accept': 'application/json'}
        timeout = aiohttp.ClientTimeout(total=None)
        per_call_timeout = float(timeout_seconds)

        items: List[Dict[str, Any]] = []
        call_count = 0
        cache_hits = 0
        any_stale = False
        oldest_fetched_at: Optional[float] = None

        ttl_fb = ns_ttls.get(NS_FB_ADS) or base_ttl or DEFAULT_TTL_FB_ADS
        ttl_li = ns_ttls.get(NS_LI_ADS) or base_ttl or DEFAULT_TTL_LI_ADS

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # ---- FB pagination ----
            cursor: Optional[str] = None
            seen_cursors: Set[str] = set()
            for _ in range(fb_max_pages):
                if cursor and cursor in seen_cursors:
                    break
                if cursor:
                    seen_cursors.add(cursor)
                params: Dict[str, Any] = {'query': brand}
                if cursor:
                    params['cursor'] = cursor
                try:
                    data, meta = await self._safe_get(
                        session, headers, f"{base_url}{FB_ADS_PATH}", params,
                        provider_label='ScrapeCreators:facebook_ads',
                        timeout_seconds=per_call_timeout,
                        cache_namespace=NS_FB_ADS, cache_ttl=ttl_fb,
                        stale_grace=stale_grace, tenant_id=tenant_id,
                    )
                except Exception as exc:
                    # 5xx after retries — log & break the FB loop, do NOT
                    # poison LinkedIn.
                    logger.warning(f"[SC:ad_impersonation] FB page failed: {exc}")
                    break
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
                if data is None:
                    break
                page_ads = data.get('searchResults') or data.get('ads') or []
                if not isinstance(page_ads, list) or not page_ads:
                    break
                for raw in page_ads:
                    if not isinstance(raw, dict):
                        continue
                    ad = _build_fb_ad(raw)
                    bucket, reason, evidence = _classify_fb(
                        ad, fb_legit_pages, legit_domains, brand,
                    )
                    items.append({
                        'platform': 'facebook',
                        'pattern_id': 'FB.AD.1',
                        'ad': ad,
                        'bucket': bucket,
                        'bucket_reason': reason,
                        'classifier_evidence': evidence,
                    })
                cursor = data.get('cursor') or data.get('next_cursor')
                if not cursor:
                    break

            # ---- LinkedIn: two modes ----
            for mode_param, value in (('company', brand), ('keyword', brand)):
                try:
                    data, meta = await self._safe_get(
                        session, headers, f"{base_url}{LI_ADS_PATH}",
                        {mode_param: value},
                        provider_label='ScrapeCreators:linkedin_ads',
                        timeout_seconds=per_call_timeout,
                        cache_namespace=NS_LI_ADS, cache_ttl=ttl_li,
                        stale_grace=stale_grace, tenant_id=tenant_id,
                    )
                except Exception as exc:
                    logger.warning(f"[SC:ad_impersonation] LI {mode_param} failed: {exc}")
                    continue
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
                if data is None:
                    continue
                raw_ads = data.get('ads') or data.get('results') or []
                if not isinstance(raw_ads, list):
                    continue
                for raw in raw_ads:
                    if not isinstance(raw, dict):
                        continue
                    ad = _build_li_ad(raw)
                    bucket, reason, evidence = _classify_li(
                        ad, li_legit_ids, li_legit_names,
                    )
                    items.append({
                        'platform': 'linkedin',
                        'pattern_id': 'LI.AD.1',
                        'ad': ad,
                        'bucket': bucket,
                        'bucket_reason': reason,
                        'classifier_evidence': evidence,
                    })

        agg_hit = bool(call_count and cache_hits == call_count and not any_stale)
        return items, call_count, agg_hit, any_stale, oldest_fetched_at

    async def _safe_get(
        self,
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
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """Absorbs 4xx (returns None data, real meta); 5xx propagates after
        upstream_request's retry loop. Matches the SMM `_safe_get` pattern.
        """
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
        try:
            if 400 <= resp.status < 500:
                text = await resp.text()
                logger.debug(
                    f"[{provider_label}] absorbed HTTP {resp.status}: {text[:120]}"
                )
                return None, meta
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(
                    f"{provider_label} HTTP {resp.status}: {text[:200]}"
                )
            data = await resp.json()
            return data if isinstance(data, dict) else {}, meta
        finally:
            await resp.release()
