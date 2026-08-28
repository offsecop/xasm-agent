"""`serper:brand_mentions` — Brand Sentiment SERP collection locks (epic #873).

FICTITIOUS brand (Lumenfield / .test) only, per the synthetic-data principle.
Covers: the fixed cohort set, the window_days→tbs mapping, own-domain
suppression (a brand's own site is marketing, not public sentiment), the raw
vendor `date` passthrough (backend parses; undated stays undated), and the
fail-closed provider contract (broken sweep ≠ clean zero).
"""
import asyncio
import os
import sys
from datetime import datetime, timezone
from typing import cast

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import aiohttp

# The dispatch fakes never touch the session — a typed null keeps pyright happy.
_NULL_SESSION = cast('aiohttp.ClientSession', None)

import tools.serper_brand_mentions as sbm
from tools.serper_brand_mentions import (
    SerperBrandMentionsTool,
    build_mention_query_cohorts,
    normalize_region,
    MAX_SERP_PAGES_PER_MENTION_SCAN,
)
import lib.serper_search as serper_lib
from lib.search_recency import serper_tbs
from lib.serper_search import SerpSweepFailed


class TestCohorts:
    def test_cohort_set_is_fixed_and_quoted(self):
        specs = build_mention_query_cohorts('Lumenfield')
        cohorts = [s['cohort'] for s in specs]
        assert cohorts == ['review', 'complaint'] + ['review_site'] * 5
        # Quoted brand in every query (no fuzzy-token contamination).
        assert all('"Lumenfield"' in s['query'] for s in specs)
        # Review-site pinpoints are 1-page (pinpoint kind).
        assert all(s['kind'] == 'pinpoint' for s in specs if s['cohort'] == 'review_site')

    def test_review_site_targets_cover_consumer_and_employer_surfaces(self):
        # #1208 — consumer (trustpilot/sitejabber/bbb) + community (reddit) +
        # employer (glassdoor). B2B (g2/capterra) is industry-gated (#1209),
        # NOT a default.
        specs = build_mention_query_cohorts('Lumenfield')
        pinpoint_queries = [s['query'] for s in specs if s['cohort'] == 'review_site']
        for host in ('trustpilot.com', 'reddit.com', 'glassdoor.com',
                     'sitejabber.com', 'bbb.org'):
            assert f'site:{host} "Lumenfield"' in pinpoint_queries
        assert not any('g2.com' in q or 'capterra.com' in q for q in pinpoint_queries)

    def test_empty_brand_yields_no_specs(self):
        assert build_mention_query_cohorts('') == []
        assert build_mention_query_cohorts('   ') == []

    def test_worst_case_page_budget_is_bounded(self):
        # 2 discovery × 3 pages + 5 pinpoint × 1 page = 11 == the hard cap;
        # the cap is a backstop, not the budget. Derive the worst case from
        # the actual cohort set so a target-list edit that breaks the math
        # fails HERE, not silently in truncated pinpoints.
        specs = build_mention_query_cohorts('Lumenfield')
        worst_case = sum(3 if s['kind'] == 'discovery' else 1 for s in specs)
        assert worst_case == 11
        assert MAX_SERP_PAGES_PER_MENTION_SCAN == 11
        # The cap must fit the full spec set — a cap below worst case silently
        # drops trailing pinpoints (specs run discovery-first).
        assert worst_case <= MAX_SERP_PAGES_PER_MENTION_SCAN


class TestSerperTbs:
    def test_buckets(self):
        assert serper_tbs(None) is None
        assert serper_tbs(1) == 'qdr:d'
        assert serper_tbs(7) == 'qdr:w'
        assert serper_tbs(30) == 'qdr:m'
        assert serper_tbs(365) == 'qdr:y'
        assert serper_tbs(1000) is None  # beyond a year → all time

    def test_month_multipliers_no_longer_collapse_to_a_year(self):
        # #1505 — 32–366 days used to collapse to qdr:y (a 60-day request
        # silently became a full year). Verified live: qdr:m6 is accepted
        # and echoed back by Serper.
        assert serper_tbs(32) == 'qdr:m2'
        assert serper_tbs(60) == 'qdr:m2'
        assert serper_tbs(90) == 'qdr:m3'
        assert serper_tbs(180) == 'qdr:m6'
        assert serper_tbs(340) == 'qdr:m11'
        # 12 "months" spans the full year → qdr:y, the vendor's native bucket.
        assert serper_tbs(350) == 'qdr:y'
        assert serper_tbs(366) == 'qdr:y'

    def test_end_anchor_emits_absolute_cdr_range(self):
        # #1505 — live-verified format: cdr:1,cd_min:M/D/YYYY,cd_max:M/D/YYYY
        # (NO leading zeros), every dated result returned inside the window.
        now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
        assert serper_tbs(92, end_days_ago=30, now=now) == \
            'cdr:1,cd_min:3/23/2026,cd_max:6/23/2026'
        # Anchored slices may be wider than a year — bounded by construction.
        assert serper_tbs(730, end_days_ago=365, now=now) == \
            'cdr:1,cd_min:7/24/2023,cd_max:7/23/2025'

    def test_end_anchor_zero_or_negative_degrades_to_trailing(self):
        now = datetime(2026, 7, 23, tzinfo=timezone.utc)
        assert serper_tbs(60, end_days_ago=0, now=now) == 'qdr:m2'
        assert serper_tbs(60, end_days_ago=-5, now=now) == 'qdr:m2'
        assert serper_tbs(60, end_days_ago=None, now=now) == 'qdr:m2'
        # No window → no range, even with an anchor (a range needs a width).
        assert serper_tbs(None, end_days_ago=30, now=now) is None


def _run(tool, params):
    return asyncio.run(tool.execute(params))


def _patch_sweep(monkeypatch, results=None, status='swept', raise_exc=None):
    async def fake_execute(specs, agent=None, max_pages=30, _dispatch=None):
        if raise_exc is not None:
            raise raise_exc
        return {
            'swept': status == 'swept',
            'status': status,
            'results': results or [],
            'diagnostics': {'pagesUsed': 1, 'queriesRun': len(specs), 'unsweptQueries': 0, 'truncated': False},
        }
    monkeypatch.setattr(sbm, 'execute_serp_queries', fake_execute)


class TestExecute:
    def test_missing_brand_rejected(self):
        out = _run(SerperBrandMentionsTool(), {})
        assert out['success'] is False
        assert out['error'] == 'missing_required'

    def test_items_shape_and_date_passthrough(self, monkeypatch):
        _patch_sweep(monkeypatch, results=[
            {'url': 'https://reviewhub.test/lumenfield', 'title': 'Lumenfield review',
             'snippet': 'terrible support, fees everywhere', 'date': '2 weeks ago',
             '_cohort': 'review', '_query': '"Lumenfield" review', '_page': 1},
            {'url': 'https://blog.test/post', 'title': 'Why I like Lumenfield',
             'snippet': 'great app', '_cohort': 'review', '_query': '"Lumenfield" review', '_page': 1},
        ])
        out = _run(SerperBrandMentionsTool(), {'brand': 'Lumenfield'})
        assert out['success'] is True
        items = out['output']['items']
        assert len(items) == 2
        assert items[0]['date'] == '2 weeks ago'   # raw passthrough
        assert 'date' not in items[1]              # undated stays undated
        assert items[0]['cohort'] == 'review'
        assert out['output']['item_kind'] == 'serp_mention'

    def test_own_domain_results_are_skipped(self, monkeypatch):
        _patch_sweep(monkeypatch, results=[
            {'url': 'https://www.lumenfield.test/blog/we-are-great', 'title': 'Our blog',
             'snippet': 'we are great', '_cohort': 'review', '_query': 'q', '_page': 1},
            {'url': 'https://cdn.lumenfield-defense.test/page', 'title': 'defensive',
             'snippet': 'x', '_cohort': 'review', '_query': 'q', '_page': 1},
            {'url': 'https://thirdparty.test/lumenfield-review', 'title': 'review',
             'snippet': 'mixed feelings', '_cohort': 'review', '_query': 'q', '_page': 1},
        ])
        out = _run(SerperBrandMentionsTool(), {
            'brand': 'Lumenfield',
            'domain': 'lumenfield.test',
            'ownedDomains': ['lumenfield-defense.test'],
        })
        assert out['success'] is True
        urls = [i['url'] for i in out['output']['items']]
        assert urls == ['https://thirdparty.test/lumenfield-review']
        assert out['output']['skipped_own_domain'] == 2

    def test_url_dedup_across_cohorts(self, monkeypatch):
        hit = {'url': 'https://same.test/x', 'title': 't', 'snippet': 's',
               '_cohort': 'review', '_query': 'q', '_page': 1}
        _patch_sweep(monkeypatch, results=[hit, dict(hit, _cohort='complaint')])
        out = _run(SerperBrandMentionsTool(), {'brand': 'Lumenfield'})
        assert len(out['output']['items']) == 1

    def test_sweep_failed_fails_the_job(self, monkeypatch):
        _patch_sweep(monkeypatch, raise_exc=SerpSweepFailed('serp_http_402'))
        out = _run(SerperBrandMentionsTool(), {'brand': 'Lumenfield'})
        assert out['success'] is False
        assert out['error'] == 'serp_http_402'
        assert out['output']['items'] == []

    def test_no_provider_is_no_credentials(self, monkeypatch):
        _patch_sweep(monkeypatch, status='unswept_no_provider')
        out = _run(SerperBrandMentionsTool(), {'brand': 'Lumenfield'})
        assert out['success'] is False
        assert out['error'] == 'no_credentials'

    def test_all_blocked_sweep_is_not_a_clean_zero(self, monkeypatch):
        _patch_sweep(monkeypatch, status='unswept')
        out = _run(SerperBrandMentionsTool(), {'brand': 'Lumenfield'})
        assert out['success'] is False
        assert out['error'] == 'serp_unswept'

    def test_window_days_maps_to_tbs(self, monkeypatch):
        _patch_sweep(monkeypatch, results=[])
        out = _run(SerperBrandMentionsTool(), {'brand': 'Lumenfield', 'window_days': 30})
        assert out['output']['tbs'] == 'qdr:m'
        # Garbage degrades to all-time, never an error.
        out = _run(SerperBrandMentionsTool(), {'brand': 'Lumenfield', 'window_days': '{{ json searchWindowDays }}'})
        assert out['success'] is True
        assert out['output']['tbs'] is None

    def test_end_days_ago_switches_to_cdr_range(self, monkeypatch):
        # #1505 — a backfill-shaped param set (window + end anchor) produces
        # an absolute cdr: range, surfaced in the diagnostics echo.
        _patch_sweep(monkeypatch, results=[])
        out = _run(SerperBrandMentionsTool(), {
            'brand': 'Lumenfield', 'window_days': 90, 'end_days_ago': 180,
        })
        assert out['success'] is True
        tbs = out['output']['tbs']
        assert tbs is not None and tbs.startswith('cdr:1,cd_min:')
        assert out['output']['end_days_ago'] == 180
        # Unresolved-template garbage degrades to the trailing-recency path.
        out = _run(SerperBrandMentionsTool(), {
            'brand': 'Lumenfield', 'window_days': 90,
            'end_days_ago': '{{ json searchEndDaysAgo }}',
        })
        assert out['success'] is True
        assert out['output']['tbs'] == 'qdr:m3'
        assert out['output']['end_days_ago'] is None
        # 0 (the continuous-scan template resolution) = end at now.
        out = _run(SerperBrandMentionsTool(), {
            'brand': 'Lumenfield', 'window_days': 90, 'end_days_ago': 0,
        })
        assert out['output']['tbs'] == 'qdr:m3'


class TestRegion:
    """#1383 — per-monitor Serper country bias (`gl`) threading."""

    def test_normalize_region_accepts_only_two_letter_alpha(self):
        assert normalize_region('ca') == 'ca'
        assert normalize_region(' CA ') == 'ca'
        assert normalize_region('gb') == 'gb'
        # Everything else degrades to None — never an error.
        assert normalize_region(None) is None
        assert normalize_region('') is None
        assert normalize_region('canada') is None
        assert normalize_region('c1') is None
        assert normalize_region('{{ json searchRegion }}') is None
        assert normalize_region(3) is None
        assert normalize_region(True) is None

    def _capture_dispatch(self, monkeypatch):
        captured = {}

        async def fake_dispatch(query, page, session,
                                timeout_seconds=None, tbs=None, gl=None,
                                empty_retry_budget=None):
            captured['gl'] = gl
            return {'hits': [], 'unswept': False}

        async def fake_execute(specs, agent=None, max_pages=30, _dispatch=None):
            assert _dispatch is not None
            await _dispatch('probe', 1)
            return {
                'swept': True, 'status': 'swept', 'results': [],
                'diagnostics': {'pagesUsed': 1, 'queriesRun': 1,
                                'unsweptQueries': 0, 'truncated': False},
            }

        monkeypatch.setattr(sbm, 'dispatch_serper', fake_dispatch)
        monkeypatch.setattr(sbm, 'execute_serp_queries', fake_execute)
        return captured

    def test_region_threads_through_to_dispatch_gl(self, monkeypatch):
        captured = self._capture_dispatch(monkeypatch)
        out = _run(SerperBrandMentionsTool(),
                   {'brand': 'Lumenfield', 'region': 'CA'})
        assert out['success'] is True
        assert captured['gl'] == 'ca'
        assert out['output']['region'] == 'ca'

    def test_unset_region_omits_gl(self, monkeypatch):
        # Behavior-preserving default: monitors without a region must produce
        # the exact pre-#1383 dispatch (gl=None → no body key).
        captured = self._capture_dispatch(monkeypatch)
        out = _run(SerperBrandMentionsTool(), {'brand': 'Lumenfield'})
        assert captured['gl'] is None
        assert out['output']['region'] is None

    def test_template_garbage_region_omits_gl(self, monkeypatch):
        # An unresolved '{{ json searchRegion }}' literal (missing context key)
        # degrades to unset, mirroring the window_days garbage tolerance.
        captured = self._capture_dispatch(monkeypatch)
        out = _run(SerperBrandMentionsTool(),
                   {'brand': 'Lumenfield', 'region': '{{ json searchRegion }}'})
        assert out['success'] is True
        assert captured['gl'] is None
        assert out['output']['region'] is None


class _FakeResp:
    def __init__(self, status, payload=None):
        self.status = status
        self._payload = payload or {}

    async def json(self):
        return self._payload

    async def release(self):
        return None


class TestDispatchBodyGl:
    """#1383 — `gl` lands in the Serper POST body ONLY when set (lib seam)."""

    def _patch(self, monkeypatch, bodies):
        async def _checkout(provider_key, requested_units=1, session=None):
            return {'apiKey': 'sk-live-serper', 'leaseToken': 'lease-1'}

        async def _reconcile(provider_key, lease_token, **kw):
            return None

        async def _upstream(session, method, url, **kw):
            bodies.append(kw['json_body'])
            return _FakeResp(200, {'organic': []}), {}

        monkeypatch.setattr(serper_lib, 'checkout_provider', _checkout)
        monkeypatch.setattr(serper_lib, 'reconcile_call', _reconcile)
        monkeypatch.setattr(serper_lib, 'upstream_request', _upstream)
        # This class asserts BODY shape, not blink handling — the empty organic
        # above would otherwise trigger #1504 retries and skew body counts.
        monkeypatch.setattr(serper_lib, 'EMPTY_PAGE1_MAX_RETRIES', 0)

    def test_gl_present_when_set_absent_when_not(self, monkeypatch):
        bodies = []
        self._patch(monkeypatch, bodies)
        asyncio.run(serper_lib.dispatch_serper(
            '"Lumenfield" review', 1, session=_NULL_SESSION, gl='ca'))
        asyncio.run(serper_lib.dispatch_serper(
            '"Lumenfield" review', 1, session=_NULL_SESSION))
        assert bodies[0]['gl'] == 'ca'
        assert 'gl' not in bodies[1]  # byte-identical pre-#1383 body
        # The rest of the body contract is untouched by the region knob.
        assert {k: bodies[0][k] for k in ('q', 'num', 'page')} == \
            {k: bodies[1][k] for k in ('q', 'num', 'page')}


if __name__ == '__main__':
    pytest.main([__file__, '-q'])
