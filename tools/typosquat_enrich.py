"""
Typosquat Enrichment Tool (typosquat:enrich)

Decoupled enrichment of ALREADY-DISCOVERED registered lookalike domains
(issue #1049). Discovery (`typosquat:detect`) emits registered rows; a backend
cadence engine risk-orders them, CAS-stamps `enrichRequestedAt`, and dispatches
LOW-priority `typosquat:enrich` jobs. This tool runs the SAME enrichment probes
the detect tool runs inline today — HTTP/SSL, page title, MX, VirusTotal /
PhishTank / OpenPhish threat feeds, SPF/DMARC/DKIM email-auth, and RDAP-primary
→ port-43-WHOIS registration-age capture — but as a standalone pass over a
supplied set of (typosquatDomainId, domain) targets.

It does NOT re-discover: no permutation generation, no isRegistered verdict, no
risk scoring. The backend's find-by-id ingestion path merges the enrichment
fields onto the existing TyposquatDomain row (keyed by `typosquatDomainId`)
without disturbing #750 / isRegistered / scoring.

The enrichment methods themselves live on `TyposquatEnrichmentMixin` (shared
verbatim with `typosquat:detect`) — this tool only orchestrates the two-phase
batched fan-out and shapes the enrichment-only output envelope.
"""

import asyncio
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Ensure agent/ is on sys.path so `from lib...` works when the plugin is loaded
# via spec_from_file_location (mirrors typosquat_detect.py).
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

from plugin_interface import ToolPlugin  # noqa: E402
from lib.typosquat_enrich_helpers import TyposquatEnrichmentMixin  # noqa: E402

logger = logging.getLogger(__name__)

# Phase-1 (HTTP/SSL/feeds/email-auth) fan-out width — matches the detect tool.
PHASE1_BATCH_SIZE = 20
# Phase-2 (WHOIS + RDAP) is slow TCP + externally rate-limited; smaller batch.
PHASE2_BATCH_SIZE = 5

# Per-job wall-clock backstop. The dispatcher gives each enrich job the standard
# DEFENSE-IN-DEPTH backstop only. The PRIMARY bound on enrichment cost is the
# backend chunk size (~8 domains/job) + the job reaper (maxRuntimeMinutes) — an
# 8-domain chunk cannot approach this deadline, so in normal operation it never
# fires. It exists purely so a pathologically-wedged chunk returns partial (the
# un-enriched tail is left unstamped-enriched and re-selected next cadence via
# the backend CAS-stamp-before-dispatch tail-rotation, #1049) rather than hanging
# until the reaper kills the job.
ENRICH_SOFT_DEADLINE_S = 240


class TyposquatEnrichTool(ToolPlugin, TyposquatEnrichmentMixin):
    """Enrich already-discovered registered lookalike domains (no re-discovery).

    Runs the shared Phase-1 (HTTP/SSL/MX/title/VT/PhishTank/OpenPhish/SPF/DMARC/
    DKIM, batch 20) and Phase-2 (RDAP→WHOIS, batch 5) enrichment from
    `TyposquatEnrichmentMixin` over a supplied `targets` set and emits an
    enrichment-only envelope keyed by `typosquatDomainId` for a find-by-id merge.
    """

    @property
    def name(self) -> str:
        return "typosquat:enrich"

    @property
    def description(self) -> str:
        return (
            "Enrich already-discovered registered look-alike domains: HTTP/SSL, "
            "page title, MX, VirusTotal/PhishTank/OpenPhish threat feeds, "
            "SPF/DMARC/DKIM email-auth, and RDAP-primary (port-43 WHOIS fallback) "
            "registration-age capture. Takes a set of {id, domain} targets and "
            "returns enrichment fields keyed by typosquatDomainId for a "
            "find-by-id merge. Does NOT re-discover, re-score, or re-decide "
            "registration (that stays on typosquat:detect)."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor ID the targets belong to (echoed back for the ingestion merge)."
                },
                "targets": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "description": "TyposquatDomain id (merge key)."},
                            "domain": {"type": "string", "description": "The registered look-alike domain to enrich."},
                        },
                        "required": ["id", "domain"],
                    },
                    "description": "Already-discovered registered look-alike domains to enrich."
                },
            },
            "required": ["targets"],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            'category': 'enrichment',
            'phase': 4,
            'domain': ['dns', 'ssl', 'osint'],
            'input_type': ['domain'],
            'output_type': ['findings'],
            'chainable_after': ['typosquat:detect'],
            'chainable_before': [],
        }

    # -- Main execution --------------------------------------------------------

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        """Enrich the supplied registered look-alike targets and return an
        enrichment-only envelope keyed by typosquatDomainId."""
        execution_start = time.time()
        agent = parameters.get('_agent')
        brand_monitor_id = parameters.get('brandMonitorId')
        raw_targets = parameters.get('targets') or []

        # Normalize targets → [(typosquatDomainId, domain)], dropping malformed
        # entries and de-duplicating by domain (keep first id seen). A domain may
        # appear once per merge — the backend updates by id, so a duplicate
        # domain would waste an external lookup.
        seen_domains: set = set()
        targets: List[Tuple[str, str]] = []
        for t in raw_targets:
            if not isinstance(t, dict):
                continue
            tid = t.get('id')
            dom = t.get('domain')
            if not tid or not dom:
                continue
            dom = str(dom).lower().strip().rstrip('.')
            if not dom or dom in seen_domains:
                continue
            seen_domains.add(dom)
            targets.append((str(tid), dom))

        if not targets:
            return {
                'success': True,
                'output': {
                    'brandMonitorId': brand_monitor_id,
                    'results': [],
                    'total_enriched': 0,
                    'tool': 'typosquat:enrich',
                    'scan_type': 'typosquat_enrich',
                },
                'raw_output': 'typosquat:enrich — no valid targets supplied',
            }

        domains = [dom for _tid, dom in targets]
        id_by_domain = {dom: tid for tid, dom in targets}

        if agent:
            agent.report_progress(
                current_operation=f"Enriching {len(domains)} registered look-alikes...",
                current_target=domains[0],
                items_processed=0,
                total_items=len(domains),
            )

        # Pre-load OpenPhish feed once (cached for the whole job).
        await self._load_openphish_feed()

        http_results: Dict[str, Dict[str, Any]] = {}
        # A4 — parsed leaf-cert dict (or None when no cert / probe failed);
        # `has_ssl_cert` derives from `is not None`.
        ssl_results: Dict[str, Optional[Dict[str, Any]]] = {}
        mx_results: Dict[str, List[str]] = {}
        title_results: Dict[str, Optional[str]] = {}
        vt_results: Dict[str, Optional[Dict[str, Any]]] = {}
        pt_results: Dict[str, bool] = {}
        op_results: Dict[str, Tuple[Optional[str], bool]] = {}
        spf_results: Dict[str, Dict[str, Any]] = {}
        dmarc_results: Dict[str, Dict[str, Any]] = {}
        dkim_results: Dict[str, Dict[str, Any]] = {}
        # A3 — per-domain deduped origin-ASN annotations for the resolved IPv4s
        # (Team Cymru DNS TXT; empty list when nothing resolved / all failed).
        asn_results: Dict[str, List[Dict[str, Any]]] = {}
        whois_results: Dict[str, Dict[str, Any]] = {}

        enriched_count = 0

        # -- Phase 1: HTTP/SSL/MX/title/VT/PhishTank/OpenPhish/SPF/DMARC/DKIM ---
        # (batch 20). Same probes and per-leg error defaults as the detect tool.
        for i in range(0, len(domains), PHASE1_BATCH_SIZE):
            if time.time() - execution_start > ENRICH_SOFT_DEADLINE_S:
                logger.warning(
                    f"[TyposquatEnrich] Phase-1 soft-deadline "
                    f"({ENRICH_SOFT_DEADLINE_S}s) reached — enriched "
                    f"{i}/{len(domains)} targets; deferring the remainder to the "
                    f"next cadence run"
                )
                break
            batch = domains[i:i + PHASE1_BATCH_SIZE]
            http_batch = await asyncio.gather(*[self._check_http(d) for d in batch], return_exceptions=True)
            ssl_batch = await asyncio.gather(*[self._check_ssl(d) for d in batch], return_exceptions=True)
            mx_batch = await asyncio.gather(*[self._mx_lookup(d) for d in batch], return_exceptions=True)
            title_batch = await asyncio.gather(*[self._get_page_title(d) for d in batch], return_exceptions=True)
            vt_batch = await asyncio.gather(*[self._check_virustotal(d) for d in batch], return_exceptions=True)
            pt_batch = await asyncio.gather(*[self._check_phishtank(d) for d in batch], return_exceptions=True)
            op_batch = await asyncio.gather(*[self._check_openphish(d) for d in batch], return_exceptions=True)
            spf_batch = await asyncio.gather(*[self._check_spf(d) for d in batch], return_exceptions=True)
            dmarc_batch = await asyncio.gather(*[self._check_dmarc(d) for d in batch], return_exceptions=True)
            dkim_batch = await asyncio.gather(*[self._check_dkim(d) for d in batch], return_exceptions=True)
            asn_batch = await asyncio.gather(*[self._asn_lookup(d) for d in batch], return_exceptions=True)
            for j, d in enumerate(batch):
                hr = http_batch[j]
                sr = ssl_batch[j]
                mr = mx_batch[j]
                tr = title_batch[j]
                vr = vt_batch[j]
                pr = pt_batch[j]
                opr = op_batch[j]
                spfr = spf_batch[j]
                dmr = dmarc_batch[j]
                dkr = dkim_batch[j]
                http_results[d] = hr if not isinstance(hr, Exception) else {'has_content': False, 'status_code': 0, 'redirect_chain': [], 'final_url': f'http://{d}'}
                ssl_results[d] = sr if not isinstance(sr, Exception) else None
                mx_results[d] = [m for m in (mr if not isinstance(mr, Exception) else []) if m and m.strip()]
                title_results[d] = tr if not isinstance(tr, Exception) else None
                vt_results[d] = vr if not isinstance(vr, Exception) else None
                pt_results[d] = pr if not isinstance(pr, Exception) else False
                # On a per-domain error: no match, feed assumed available (a feed
                # outage surfaces as available=False from the leg itself).
                op_results[d] = opr if isinstance(opr, tuple) else (None, True)
                spf_results[d] = spfr if not isinstance(spfr, Exception) else {'has_spf': False, 'spf_record': None, 'spf_policy': None, 'spf_unswept': False}
                dmarc_results[d] = dmr if not isinstance(dmr, Exception) else {'has_dmarc': False, 'dmarc_record': None, 'dmarc_policy': None, 'dmarc_unswept': False}
                dkim_results[d] = dkr if not isinstance(dkr, Exception) else {'has_dkim': False, 'dkim_selector': None}
                ar = asn_batch[j]
                asn_results[d] = ar if not isinstance(ar, Exception) else []

            if agent:
                agent.report_progress(
                    current_operation="Enriching (web/SSL/email-auth/feeds)...",
                    current_target=batch[-1],
                    items_processed=min(i + PHASE1_BATCH_SIZE, len(domains)),
                    total_items=len(domains),
                )

        # -- Phase 2: WHOIS + RDAP age (slow TCP, batch 5) ---------------------
        # RDAP is PRIMARY (clean ISO from events[].eventAction=="registration");
        # port-43 WHOIS is the fallback for ccTLDs without RDAP. Same merge as
        # the detect tool: RDAP `created` overrides the port-43 `created`, and
        # the `rdap_age_throttled` marker is carried through.
        for i in range(0, len(domains), PHASE2_BATCH_SIZE):
            if time.time() - execution_start > ENRICH_SOFT_DEADLINE_S:
                logger.warning(
                    f"[TyposquatEnrich] Phase-2 (WHOIS/RDAP) soft-deadline "
                    f"({ENRICH_SOFT_DEADLINE_S}s) reached — aged "
                    f"{i}/{len(domains)} targets; deferring the remainder to the "
                    f"next cadence run"
                )
                break
            batch = domains[i:i + PHASE2_BATCH_SIZE]
            whois_batch = await asyncio.gather(*[self._whois_lookup(d) for d in batch], return_exceptions=True)
            rdap_batch = await asyncio.gather(*[self._rdap_created(d) for d in batch], return_exceptions=True)
            for j, d in enumerate(batch):
                wr = whois_batch[j]
                wr = wr if not isinstance(wr, Exception) else {'registrar': None, 'created': None, 'expires': None, 'nameservers': [], 'whois_failed': True}
                rd = rdap_batch[j]
                if isinstance(rd, Exception):
                    rdap_created, rdap_age_throttled = None, False
                else:
                    rdap_created, rdap_age_throttled = rd
                if rdap_created:
                    # RDAP is primary: its clean ISO date overrides the port-43
                    # first-match `created:` artifact (e.g. CIRA .ca).
                    wr = {**wr, 'created': rdap_created}
                # Carry the raw RDAP date + throttle marker separately so the
                # envelope can surface `rdap_created` (which source won) and the
                # backend can distinguish UNKNOWN-because-throttled from a gap.
                wr = {**wr, 'rdap_created': rdap_created, 'rdap_age_throttled': rdap_age_throttled}
                whois_results[d] = wr

        # -- Assemble enrichment-only results (keyed by typosquatDomainId) -----
        results: List[Dict[str, Any]] = []
        for d in domains:
            # Only emit rows that were actually reached this pass (Phase 1 ran);
            # the deferred tail is left for the next cadence CAS-selection.
            if d not in http_results:
                continue
            enriched_count += 1
            http_data = http_results[d]
            whois = whois_results.get(d, {})
            mx = mx_results.get(d, [])
            op_url, op_available = op_results.get(d, (None, True))
            spf = spf_results.get(d, {'has_spf': False, 'spf_record': None, 'spf_policy': None, 'spf_unswept': False})
            dmarc = dmarc_results.get(d, {'has_dmarc': False, 'dmarc_record': None, 'dmarc_policy': None, 'dmarc_unswept': False})
            dkim = dkim_results.get(d, {'has_dkim': False, 'dkim_selector': None})
            vt = vt_results.get(d)

            # Envelope shape follows the `typosquat_enrich` ingestion consumer
            # (backend T5 find-by-id merge): NESTED `whois` object + FLAT
            # spf/dmarc/dkim + top-level `rdap_created` / `rdap_age_throttled`.
            row: Dict[str, Any] = {
                'typosquatDomainId': id_by_domain[d],
                'domain': d,
                # Web / SSL
                'has_web_content': http_data.get('has_content', False),
                'http_status_code': http_data.get('status_code', 0),
                'redirect_chain': http_data.get('redirect_chain', []),
                'final_url': http_data.get('final_url', f'http://{d}'),
                'has_ssl_cert': ssl_results.get(d) is not None,
                # A4 — parsed leaf-certificate detail (issuer CN/O, subject CN,
                # SAN, validity, SHA-256 fingerprint) for same-operator
                # correlation; None when no cert was presented/captured. The
                # backend merge must NOT let a None wipe a previously-stored
                # cert (merge-don't-clobber, same as WHOIS).
                'ssl_cert': ssl_results.get(d),
                'page_title': title_results.get(d),
                # Mail
                'mx_records': mx,
                # A3 — deduped origin-ASN annotations for the resolved IPv4s
                # (Team Cymru). Empty list = nothing resolved / all lookups
                # failed; the backend merge must NOT let an empty list wipe a
                # previously-stored set (merge-don't-clobber, same as WHOIS).
                'asn_info': asn_results.get(d, []),
                # WHOIS / RDAP registration facts (nested `whois`; RDAP override
                # of `created` already applied in Phase 2).
                'whois': {
                    'registrar': whois.get('registrar'),
                    'created': whois.get('created'),
                    'expires': whois.get('expires'),
                    'nameservers': whois.get('nameservers', []),
                    'registrant_email': whois.get('registrant_email'),
                    'registrant_org': whois.get('registrant_org'),
                    'registrant_name': whois.get('registrant_name'),
                    'registrant_country': whois.get('registrant_country'),
                    # WP-3 — preserve-prior marker: a failed lookup must not null
                    # out previously-persisted registrar/created on the merge. A
                    # domain ABSENT from whois_results (Phase-2 deadline-skipped
                    # or never probed) is NOT an "authentic empty" — it was never
                    # attempted, so report whois_failed=True (preserve-prior),
                    # never False (which would signal a real blank).
                    'whois_failed': (
                        whois.get('whois_failed', False)
                        if d in whois_results
                        else True
                    ),
                },
                # The clean RDAP registration date when RDAP answered (None for
                # ccTLDs without RDAP / throttled / parse-miss — the port-43
                # `whois.created` then governs). Surfaced so the merge sees which
                # source won.
                'rdap_created': whois.get('rdap_created'),
                # WHOIS-2 — age UNKNOWN-because-throttled (RDAP tenant rate-limit)
                # vs a genuine no-date gap; the backend HOLDS such a row for
                # re-sweep instead of fail-closing its null age to 'stale'.
                'rdap_age_throttled': bool(whois.get('rdap_age_throttled', False)),
                # Threat feeds
                'vt_detections': vt,
                'phishtank_match': pt_results.get(d, False),
                'openphish_match': bool(op_url),
                'openphish_url': op_url,
                # FEED-3 — honesty marker: a False match here is UNSWEPT (feed
                # outage), not clean.
                'openphish_unavailable': not op_available,
                # Email authentication posture (flat, per the ingestion consumer).
                'spf': spf,
                'dmarc': dmarc,
                'dkim': dkim,
            }
            results.append(row)

        duration = round(time.time() - execution_start, 2)
        summary = (
            f"typosquat:enrich — enriched {enriched_count}/{len(domains)} "
            f"registered look-alikes ({duration}s)"
        )
        logger.info(f"[TyposquatEnrich] {summary}")

        if agent:
            agent.report_progress(
                current_operation="Enrichment complete",
                current_target=domains[0],
                items_processed=len(domains),
                total_items=len(domains),
            )

        return {
            'success': True,
            'output': {
                'brandMonitorId': brand_monitor_id,
                'results': results,
                'total_enriched': enriched_count,
                'tool': 'typosquat:enrich',
                'scan_type': 'typosquat_enrich',
            },
            'raw_output': summary,
            'execution_metrics': {
                'duration_seconds': duration,
                'targets_supplied': len(domains),
                'targets_enriched': enriched_count,
            },
        }


def get_tool():
    return TyposquatEnrichTool()
