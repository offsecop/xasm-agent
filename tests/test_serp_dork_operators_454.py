"""G5 (#454) exec/VIP SERP dork operators + #981 live Serper.dev wiring.

FICTITIOUS exec/brand (Jane Synth / Lumenfield / .test) only — the real
2026-07-03 FP host SHAPES are reproduced with synthetic brands per the
synthetic-data principle (no real client strings in business-logic tests).
"""
import asyncio
import os
import sys
from typing import cast

import aiohttp
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# The dispatch tests monkeypatch checkout/reconcile/upstream_request on the
# lib module, so no real ClientSession is ever used — a typed null stand-in
# keeps the call sites honest under pyright without opening a socket.
_NULL_SESSION = cast('aiohttp.ClientSession', None)

import tools.brand_monitor_vip_exposure as vip
import lib.serper_search as serper_lib
from tools.brand_monitor_vip_exposure import (
    _exec_dork_templates,
    _pivot_dork_templates,
    _classify_serp_host,
    _classify_exposure,
    _build_serp_dork_cohorts,
    _serp_hit_to_finding,
    MAX_SERP_PAGES_PER_VIP,
)
from lib.serper_search import (
    dispatch_serper as _dispatch_serper,
    execute_serp_queries as _execute_exec_dorks,
    registrable_domain as _registrable_domain,
    SerpNotConfigured as _SerpNotConfigured,
    SerpSweepFailed as _SerpSweepFailed,
    DISCOVERY_MAX_PAGES,
    PINPOINT_MAX_PAGES,
    SERPER_RESULTS_PER_PAGE,
)
from lib.integration_credentials import (
    IntegrationAuthError,
    IntegrationServerError,
    QuotaExceededError,
)


class TestOperatorUpgrades:
    def test_around_association_dork(self):
        dorks = _exec_dork_templates('Jane Synth', 'Lumenfield', 'lumenfield.test')
        assert any('AROUND(5)' in d and '"Lumenfield"' in d for d in dorks)

    def test_recency_after_dork(self):
        dorks = _exec_dork_templates('Jane Synth', 'Lumenfield', 'lumenfield.test')
        assert any('after:' in d for d in dorks)
        # Explicit after_date is honoured verbatim.
        explicit = _exec_dork_templates('Jane Synth', 'Lumenfield', 'x.test', after_date='2024-01-01')
        assert any('after:2024-01-01' in d for d in explicit)

    def test_subtract_legit_footprint_dork(self):
        dorks = _exec_dork_templates('Jane Synth', 'Lumenfield', 'lumenfield.test')
        assert any('-site:linkedin.com' in d and '-site:lumenfield.test' in d for d in dorks)
        # Without a domain the subtraction still excludes LinkedIn.
        nodom = _exec_dork_templates('Jane Synth', 'Lumenfield')
        assert any(d.endswith('-site:linkedin.com') for d in nodom)

    def test_no_deprecated_daterange_operator(self):
        dorks = _exec_dork_templates('Jane Synth', 'Lumenfield', 'lumenfield.test')
        assert not any('daterange:' in d for d in dorks)

    def test_order_preserving_dedup_and_empty_name(self):
        assert _exec_dork_templates('') == []
        dorks = _exec_dork_templates('Jane Synth', 'Lumenfield', 'lumenfield.test')
        assert len(dorks) == len(set(dorks))


class TestPivotLoop:
    def test_confirmed_email_reused_in_credential_dorks(self):
        pivots = _pivot_dork_templates('jane@lumenfield.test')
        assert any('password' in d for d in pivots)
        assert any('breach' in d or 'combolist' in d for d in pivots)
        assert all('"jane@lumenfield.test"' in d for d in pivots)

    def test_handle_stripped_of_at(self):
        pivots = _pivot_dork_templates('@janesynth')
        assert pivots and all('"janesynth"' in d for d in pivots)

    def test_empty_identifier(self):
        assert _pivot_dork_templates('') == []


def _spec(query, kind='discovery', cohort='test'):
    return {'cohort': cohort, 'query': query, 'kind': kind}


class TestExecutionSeam:
    def test_key_absent_is_fail_closed_noop(self):
        # No injected dispatch ⇒ no provider ⇒ honest unswept, NOT empty-clean.
        res = asyncio.run(_execute_exec_dorks([_spec('anything')]))
        assert res['swept'] is False
        assert res['status'] == 'unswept_no_provider'
        assert res['results'] == []

    def test_pinpoint_fetches_exactly_one_page(self):
        calls = []

        async def dispatch(query, page):
            calls.append((query, page))
            return {'hits': [{'url': f'https://x.test/{page}'}] * SERPER_RESULTS_PER_PAGE}

        res = asyncio.run(_execute_exec_dorks([_spec('q', kind='pinpoint')], _dispatch=dispatch))
        assert res['swept'] is True
        assert [p for _, p in calls] == [1]  # pinpoint never paginates

    def test_discovery_paginates_until_bound(self):
        calls = []

        async def dispatch(query, page):
            calls.append(page)
            # Always a full page ⇒ keeps paginating until the per-cohort bound.
            return {'hits': [{'url': f'https://x.test/{page}/{i}'} for i in range(SERPER_RESULTS_PER_PAGE)]}

        res = asyncio.run(_execute_exec_dorks([_spec('q', kind='discovery')], _dispatch=dispatch))
        assert res['swept'] is True
        assert calls == list(range(1, DISCOVERY_MAX_PAGES + 1))
        assert max(calls) > 1  # DID paginate past page 1

    def test_discovery_stops_on_short_page(self):
        calls = []

        async def dispatch(query, page):
            calls.append(page)
            # A short (< full) page means the tail is dry ⇒ stop.
            return {'hits': [{'url': 'https://x.test/only'}]}

        asyncio.run(_execute_exec_dorks([_spec('q', kind='discovery')], _dispatch=dispatch))
        assert calls == [1]

    def test_global_page_cap_bounds_spend(self):
        # Many discovery cohorts, each willing to paginate — the GLOBAL cap must
        # bound total metered pages (worst-case $/VIP is calculable + tested).
        calls = []

        async def dispatch(query, page):
            calls.append((query, page))
            return {'hits': [{'url': f'https://x.test/{query}/{page}/{i}'} for i in range(SERPER_RESULTS_PER_PAGE)]}

        specs = [_spec(f'q{i}', kind='discovery') for i in range(50)]
        res = asyncio.run(_execute_exec_dorks(specs, _dispatch=dispatch))
        assert len(calls) <= MAX_SERP_PAGES_PER_VIP
        assert res['diagnostics']['truncated'] is True

    def test_unswept_only_is_not_empty_clean(self):
        # Every query blocked (free-tier 400) ⇒ status 'unswept', never swept.
        async def dispatch(query, page):
            return {'hits': [], 'unswept': True}

        res = asyncio.run(_execute_exec_dorks([_spec('filetype:env q')], _dispatch=dispatch))
        assert res['swept'] is False
        assert res['status'] == 'unswept'  # NOT {swept:True, results:[]}
        assert res['results'] == []

    def test_not_configured_first_dispatch_is_unswept_no_provider(self):
        async def dispatch(query, page):
            raise _SerpNotConfigured('HTTP 404 No active SERP_SEARCH integration')

        res = asyncio.run(_execute_exec_dorks([_spec('q')], _dispatch=dispatch))
        assert res['swept'] is False
        assert res['status'] == 'unswept_no_provider'

    def test_sweep_failure_propagates(self):
        # A revoked key / quota mid-sweep is scan-invalidating: propagate so the
        # caller FAILs the job (never a false clean).
        async def dispatch(query, page):
            raise _SerpSweepFailed('serp_http_401')

        with pytest.raises(_SerpSweepFailed):
            asyncio.run(_execute_exec_dorks([_spec('q')], _dispatch=dispatch))


class _FakeResp:
    def __init__(self, status, payload=None):
        self.status = status
        self._payload = payload or {}

    async def json(self):
        return self._payload

    async def release(self):
        return None


class TestSerperDispatch:
    """Live-dispatch parse + metering + fail-closed, with checkout/reconcile/
    upstream_request monkeypatched on the module."""

    def _patch(self, monkeypatch, *, checkout=None, upstream=None):
        reconciles = []

        async def _checkout(provider_key, requested_units=1, session=None):
            if checkout is not None:
                return await checkout(provider_key, requested_units, session)
            return {'apiKey': 'sk-live-serper', 'leaseToken': 'lease-1'}

        async def _reconcile(provider_key, lease_token, **kw):
            reconciles.append(kw)

        async def _upstream(session, method, url, **kw):
            assert url == 'https://google.serper.dev/search'  # host PINNED (SSRF)
            assert kw['headers'].get('X-API-KEY') == 'sk-live-serper'
            assert upstream is not None
            return await upstream(session, method, url, **kw)

        monkeypatch.setattr(serper_lib, 'checkout_provider', _checkout)
        monkeypatch.setattr(serper_lib, 'reconcile_call', _reconcile)
        monkeypatch.setattr(serper_lib, 'upstream_request', _upstream)
        return reconciles

    def test_parses_organic_and_reconciles_success(self, monkeypatch):
        async def upstream(session, method, url, **kw):
            payload = {'organic': [
                {'link': 'https://a.test', 'title': 'A', 'snippet': 's1'},
                {'link': 'https://b.test', 'title': 'B', 'snippet': 's2'},
                {'title': 'no-link-dropped'},
            ]}
            return _FakeResp(200, payload), {}

        reconciles = self._patch(monkeypatch, upstream=upstream)
        out = asyncio.run(_dispatch_serper('q', 1, session=_NULL_SESSION))
        assert [h['url'] for h in out['hits']] == ['https://a.test', 'https://b.test']
        assert out['unswept'] is False
        assert len(reconciles) == 1  # exactly one metered reconcile per page
        assert reconciles[0]['units'] == 1
        assert reconciles[0]['success'] is True
        assert reconciles[0]['error_code'] is None

    def test_free_tier_400_is_unswept_not_clean(self, monkeypatch):
        async def upstream(session, method, url, **kw):
            return _FakeResp(400), {}

        reconciles = self._patch(monkeypatch, upstream=upstream)
        out = asyncio.run(_dispatch_serper('filetype:env q', 1, session=_NULL_SESSION))
        assert out['unswept'] is True
        assert out['hits'] == []
        assert reconciles[0]['success'] is False
        assert reconciles[0]['error_code'] == 'serp_http_400'

    def test_401_midsweep_raises_and_reconciles_failure(self, monkeypatch):
        async def upstream(session, method, url, **kw):
            return _FakeResp(401), {}

        reconciles = self._patch(monkeypatch, upstream=upstream)
        with pytest.raises(_SerpSweepFailed):
            asyncio.run(_dispatch_serper('q', 1, session=_NULL_SESSION))
        assert reconciles[0]['success'] is False  # metered even on the failure path

    def test_checkout_401_is_sweep_failed(self, monkeypatch):
        async def checkout(provider_key, requested_units, session):
            raise IntegrationAuthError('bad key')

        self._patch(monkeypatch, checkout=checkout, upstream=None)
        with pytest.raises(_SerpSweepFailed):
            asyncio.run(_dispatch_serper('q', 1, session=_NULL_SESSION))

    def test_checkout_quota_is_sweep_failed(self, monkeypatch):
        async def checkout(provider_key, requested_units, session):
            raise QuotaExceededError(provider_key='SERP_SEARCH', retry_after=60)

        self._patch(monkeypatch, checkout=checkout, upstream=None)
        with pytest.raises(_SerpSweepFailed):
            asyncio.run(_dispatch_serper('q', 1, session=_NULL_SESSION))

    def test_checkout_404_is_not_configured(self, monkeypatch):
        async def checkout(provider_key, requested_units, session):
            raise IntegrationServerError('checkout(SERP_SEARCH) HTTP 404: No active integration')

        self._patch(monkeypatch, checkout=checkout, upstream=None)
        with pytest.raises(_SerpNotConfigured):
            asyncio.run(_dispatch_serper('q', 1, session=_NULL_SESSION))

    def test_5xx_is_unswept_not_clean(self, monkeypatch):
        # A persistent 5xx (after upstream_request's own retries) must NOT look
        # like a clean empty page — it is unswept.
        async def upstream(session, method, url, **kw):
            return _FakeResp(503), {}

        reconciles = self._patch(monkeypatch, upstream=upstream)
        out = asyncio.run(_dispatch_serper('q', 1, session=_NULL_SESSION))
        assert out['unswept'] is True
        assert out['hits'] == []
        assert reconciles[0]['success'] is False

    def test_402_cost_breaker_raises_sweep_failed(self, monkeypatch):
        async def upstream(session, method, url, **kw):
            return _FakeResp(402), {}

        reconciles = self._patch(monkeypatch, upstream=upstream)
        with pytest.raises(_SerpSweepFailed):
            asyncio.run(_dispatch_serper('q', 1, session=_NULL_SESSION))
        assert reconciles[0]['success'] is False

    def test_transport_error_is_unswept_not_clean(self, monkeypatch):
        async def upstream(session, method, url, **kw):
            raise RuntimeError('connection reset')

        reconciles = self._patch(monkeypatch, upstream=upstream)
        out = asyncio.run(_dispatch_serper('q', 1, session=_NULL_SESSION))
        assert out['unswept'] is True
        assert reconciles[0]['success'] is False
        assert reconciles[0]['error_code'] == 'serp_dispatch_error'


class TestExecutorFailClosed:
    def test_all_pages_broken_is_unswept_never_swept_clean(self):
        # Every page returns an unswept (5xx/transport) result ⇒ the sweep is
        # 'unswept', NEVER {swept:True, results:[]} — the false-clean this PR
        # exists to prevent.
        async def dispatch(query, page):
            return {'hits': [], 'unswept': True}

        specs = [_spec('q1', kind='discovery'), _spec('q2', kind='pinpoint')]
        res = asyncio.run(_execute_exec_dorks(specs, _dispatch=dispatch))
        assert res['swept'] is False
        assert res['status'] == 'unswept'
        assert res['results'] == []

    def test_partial_sweep_with_some_unswept_is_honest_swept(self):
        # If at least one page really swept, partial results are honest.
        async def dispatch(query, page):
            if query == 'good':
                return {'hits': [{'url': 'https://x.test/hit'}]}
            return {'hits': [], 'unswept': True}

        specs = [_spec('bad', kind='pinpoint'), _spec('good', kind='pinpoint')]
        res = asyncio.run(_execute_exec_dorks(specs, _dispatch=dispatch))
        assert res['swept'] is True
        assert len(res['results']) == 1


class TestRegistrableDomain:
    def test_simple(self):
        assert _registrable_domain('a.lumenfield.test') == 'lumenfield.test'

    def test_multi_level_tld(self):
        assert _registrable_domain('shop.lumenfield.co.uk') == 'lumenfield.co.uk'

    def test_bare(self):
        assert _registrable_domain('lumenfield.test') == 'lumenfield.test'


class TestHostClassifier:
    TOKENS = ['lumenfield']

    def test_combosquat_on_etld1_fires_high(self):
        c = _classify_serp_host('https://lumenfield-login.test/signin', [], [], self.TOKENS)
        assert c is not None
        assert c['action'] == 'flag'
        assert c['category'] == 'COMBOSQUAT'
        assert c['severity'] == 'HIGH'
        assert c['exposureType'] == 'IMPERSONATION'

    def test_brand_only_in_path_does_not_fire(self):
        # eTLD+1 = evilhost.test (no brand token) ⇒ NOT a combosquat.
        c = _classify_serp_host('https://secure.evilhost.test/lumenfield', [], [], self.TOKENS)
        assert c is None

    def test_known_platform_subdomain_not_squat(self):
        # The real 2026-07-03 FP shape: brand.<third-party-platform>.
        c = _classify_serp_host('https://lumenfield.pissedconsumer.com/reviews', [], [], self.TOKENS)
        assert c is not None
        assert c['action'] == 'suppress'
        assert c['reason'] == 'known_directory'

    def test_brand_on_softwaredir_not_squat(self):
        c = _classify_serp_host('https://lumenfield-global.soft112.com/app', [], [], self.TOKENS)
        assert c is not None
        assert c['action'] == 'suppress'

    def test_owned_domain_suppressed(self):
        c = _classify_serp_host('https://www.lumenfield.test/about', ['lumenfield.test'], [], self.TOKENS)
        assert c is not None
        assert c['action'] == 'suppress'
        assert c['reason'] == 'owned'

    def test_tracked_typosquat_suppressed(self):
        c = _classify_serp_host('https://lumenfeild.test/', [], ['lumenfeild.test'], self.TOKENS)
        assert c is not None
        assert c['action'] == 'suppress'
        assert c['reason'] == 'known_typosquat'

    def test_data_broker_is_medium_pii(self):
        c = _classify_serp_host('https://rocketreach.co/jane-synth', [], [], self.TOKENS)
        assert c is not None
        assert c['action'] == 'flag'
        assert c['severity'] == 'MEDIUM'
        assert c['exposureType'] == 'CONTACT_EXPOSURE'  # mirrors to triage at MEDIUM

    def test_bucket_brand_in_name_fires(self):
        c = _classify_serp_host('https://lumenfield-backups.s3.amazonaws.com/db.sql', [], [], self.TOKENS)
        assert c is not None
        assert c['action'] == 'flag'
        assert c['category'] == 'OBJECT_STORE_BUCKET'

    def test_bucket_brand_only_in_content_suppressed(self):
        # Virtual-host bucket name has no brand token; brand is only in the KEY.
        c = _classify_serp_host('https://randombucket.s3.amazonaws.com/lumenfield.pdf', [], [], self.TOKENS)
        assert c is not None
        assert c['action'] == 'suppress'
        assert c['reason'] == 'bucket_brand_in_content'

    def test_bucket_pathstyle_brand_in_name_fires(self):
        c = _classify_serp_host('https://s3.amazonaws.com/lumenfield-data/x', [], [], self.TOKENS)
        assert c is not None
        assert c['action'] == 'flag'


class TestCohortBuilder:
    def test_excludes_noisy_lanes(self):
        specs = _build_serp_dork_cohorts('Jane Synth', 'Lumenfield', 'lumenfield.test')
        joined = ' '.join(s['query'] for s in specs).lower()
        # These lanes are owned by other engines / proven noise — never in SERP.
        assert 'intitle:"index of"' not in joined
        assert 'site:github.com' not in joined  # github code-secret stays in the API lane

    def test_has_flagship_cohorts(self):
        specs = _build_serp_dork_cohorts('Jane Synth', 'Lumenfield', 'lumenfield.test')
        cohorts = {s['cohort'] for s in specs}
        for expected in ('combosquat', 'brand_abuse_support', 'brand_abuse_job',
                         'brand_abuse_investment', 'code_host', 'data_broker',
                         'residence', 'email_convention'):
            assert expected in cohorts

    def test_residence_cohort_targets_municipal_portals(self):
        specs = _build_serp_dork_cohorts('Jane Synth', 'Lumenfield', 'lumenfield.test')
        res = ' '.join(s['query'] for s in specs if s['cohort'] == 'residence')
        assert 'escribemeetings.com' in res  # municipal meeting portal (home-address DOX)
        assert 'minor variance' in res

    def test_exec_corroboration_present(self):
        specs = _build_serp_dork_cohorts('Jane Synth', 'Lumenfield', 'lumenfield.test')
        joined = ' '.join(s['query'] for s in specs)
        assert 'AROUND(' in joined  # company-corroboration on exec dorks

    def test_code_search_engines_cohort(self):
        # Code-search aggregators are a distinct surface from the code_host dork;
        # domain-scoped, and must NOT leak into the GitHub API lane's territory.
        specs = _build_serp_dork_cohorts('Jane Synth', 'Lumenfield', 'lumenfield.test')
        cs = ' '.join(s['query'] for s in specs if s['cohort'] == 'code_search')
        assert cs, 'expected a code_search cohort'
        for engine in ('grep.app', 'searchcode.com', 'publicwww.com', 'sourcegraph.com'):
            assert engine in cs
        assert 'site:github.com' not in cs  # owned by the GitHub API lane (#454)
        assert 'lumenfield.test' in cs      # domain-scoped for precision

    def test_object_store_cohort_broadened(self):
        # The object-store bucket dork covers the major public object stores
        # (not just S3/GCS/Azure) whose buckets are routinely world-readable.
        specs = _build_serp_dork_cohorts('Jane Synth', 'Lumenfield', 'lumenfield.test')
        os_q = ' '.join(s['query'] for s in specs if s['cohort'] == 'object_store')
        for host in ('s3.amazonaws.com', 'storage.googleapis.com', 'blob.core.windows.net',
                     'digitaloceanspaces.com', 'r2.dev', 'oss.aliyuncs.com', 'firebaseio.com'):
            assert host in os_q


class TestHitToFinding:
    def test_combosquat_hit_becomes_high_impersonation_finding(self):
        hit = {'url': 'https://lumenfield-login.test/', 'title': 'Login', 'snippet': 'x',
               '_cohort': 'combosquat', '_query': 'q', '_page': 1}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', 'Lumenfield', 'lumenfield.test',
                                 [], [], ['lumenfield'])
        assert f is not None
        assert f['severity'] == 'HIGH'
        assert f['exposureType'] == 'IMPERSONATION'
        assert f['sourceName'] == 'Serper SERP'
        assert f['title']  # non-empty (ingestion requires it)
        assert f['metadata']['engine'] == 'serper-search'

    def test_owned_host_hit_is_dropped(self):
        hit = {'url': 'https://www.lumenfield.test/', 'title': 'Home', 'snippet': ''}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', 'Lumenfield', 'lumenfield.test',
                                 ['lumenfield.test'], [], ['lumenfield'])
        assert f is None

    def test_residence_municipal_hit_elevated_to_high_dox(self):
        # A municipal meeting PDF naming the exec (home address / minor variance)
        # is physical-safety PII → HIGH, even though the content classifier alone
        # would cap a bare contact-noun at MEDIUM.
        hit = {'url': 'https://pub-town.escribemeetings.test/filestream.ashx?DocumentId=1',
               'title': 'Committee of Adjustment — minor variance',
               'snippet': 'Applicant Jane Synth, 12 Example Rd, address of record',
               '_cohort': 'residence', '_query': 'q', '_page': 1}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', '', '', [], [], [])
        assert f is not None
        assert f['severity'] == 'HIGH'
        assert f['exposureType'] == 'CONTACT_EXPOSURE'
        assert f['metadata']['hostClass'] == 'RESIDENCE_EXPOSURE'

    def test_residence_cohort_on_databroker_keeps_medium(self):
        # A residence-dork hit that lands on a data-broker host must NOT be
        # over-elevated — it keeps the data-broker MEDIUM verdict.
        hit = {'url': 'https://rocketreach.co/jane-synth', 'title': 'Jane Synth',
               'snippet': 'address', '_cohort': 'residence'}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', 'Lumenfield', 'lumenfield.test',
                                 [], [], ['lumenfield'])
        assert f is not None
        assert f['severity'] == 'MEDIUM'
        assert f['metadata']['hostClass'] == 'DATA_BROKER_PII'


class TestLeakWordCorroboration:
    """#1 — a leak/breach/dox word only earns HIGH CONTACT_EXPOSURE when it is
    corroborated as tied to THIS VIP; incidental leak words + public-record
    mentions must NOT flood HIGH."""

    def _classify(self, title, snippet, url='https://blog.test/post',
                  name='Jane Synth', company='Lumenfield',
                  domain='lumenfield.test', email=''):
        return _classify_exposure('WEB', title, snippet, url, name, company,
                                  domain, email)

    def test_incidental_breach_word_is_not_high(self):
        # 'levee breaches' — the name is present but the leak word is an
        # unrelated common-word usage. Must NOT be HIGH CONTACT_EXPOSURE.
        c = self._classify(
            'Jane Synth on hurricane recovery',
            'Jane Synth discusses how the levee breaches reshaped the coastline.',
        )
        assert c['severity'] == 'LOW'
        assert c['exposureType'] == 'PUBLIC_MENTION'

    def test_roof_leak_incidental_is_not_high(self):
        c = self._classify(
            'Jane Synth home reno diary',
            'Jane Synth fixed a roof leak over the weekend.',
        )
        assert c['severity'] == 'LOW'

    def test_leak_word_far_from_name_is_not_high(self):
        # Name and leak word both present but > window apart (different subjects
        # on a long page) → not corroborated.
        filler = ' '.join(['padding'] * 40)
        c = self._classify(
            'Industry roundup',
            f'Jane Synth spoke at the summit. {filler} A separate data breach '
            f'hit an unrelated firm last year.',
        )
        assert c['severity'] == 'LOW'

    def test_leak_word_near_name_is_high(self):
        # Name within the proximity window of the leak word AND exact name match
        # → genuine corroborated exposure → HIGH.
        c = self._classify(
            'Credential dump',
            'Jane Synth credentials appeared in a breach combolist this week.',
        )
        assert c['severity'] == 'HIGH'
        assert c['exposureType'] == 'CONTACT_EXPOSURE'

    def test_leak_word_with_vip_email_is_high(self):
        # The VIP's exact email co-occurring with a leak word is the strongest
        # corroboration → HIGH even when the name proximity to the leak word is
        # loose (email carries the identity tie).
        filler = ' '.join(['x'] * 30)
        c = self._classify(
            'Paste dump: Jane Synth',
            f'Jane Synth jane@lumenfield.test {filler} found in a pastebin dump.',
            email='jane@lumenfield.test',
        )
        assert c['severity'] == 'HIGH'
        assert c['exposureType'] == 'CONTACT_EXPOSURE'

    def test_leak_word_with_company_domain_mailbox_is_high(self):
        c = self._classify(
            'Combolist — Jane Synth',
            'Jane Synth mailbox j.synth@lumenfield.test surfaced in a combolist.',
        )
        assert c['severity'] == 'HIGH'

    def test_public_record_host_name_match_is_low_mention(self):
        # A regulator page naming the exec beside a 'breach' word (a regulatory
        # 'rule breach', a CISO conference bio) is a public MENTION, not PII.
        c = self._classify(
            'Speaker: Jane Synth',
            'Jane Synth discusses a notable rule breach enforcement action.',
            url='https://www.ciro.ca/newsroom/speakers/jane-synth',
        )
        assert c['severity'] == 'LOW'
        assert c['exposureType'] == 'PUBLIC_MENTION'

    def test_public_record_gov_subdomain_is_low(self):
        c = self._classify(
            'Committee testimony — Jane Synth',
            'Jane Synth testimony references a data breach at another company.',
            url='https://www.ourcommons.ca/committee/jane-synth',
        )
        assert c['severity'] == 'LOW'

    def test_podcast_host_is_low_mention(self):
        c = self._classify(
            'Episode 12: Jane Synth',
            'Jane Synth on the anatomy of a breach.',
            url='https://feeds.simplecast.com/shows/jane-synth-ep12',
        )
        assert c['severity'] == 'LOW'

    def test_uncorroborated_leak_with_contact_noun_stays_medium(self):
        # No corroboration for the leak word, but a bare contact noun present →
        # MEDIUM (the contact-noun class is unchanged), never HIGH.
        c = self._classify(
            'Jane Synth bio',
            'Jane Synth — email listed. Site also mentions a breach elsewhere.',
        )
        assert c['severity'] == 'MEDIUM'
        assert c['exposureType'] == 'CONTACT_EXPOSURE'


class TestDataBrokerWrongPerson:
    """#2 — data-broker PERSON pages that are a different homonym must be
    suppressed; matching person pages + company pages are kept."""

    TOKENS = ['lumenfield']

    def test_wrong_person_slug_suppressed(self):
        # zoominfo person page for a DIFFERENT 'John Doe' when the VIP is Jane
        # Synth → suppress (wrong-person attribution).
        c = _classify_serp_host('https://www.zoominfo.com/p/John-Doe/123',
                                [], [], self.TOKENS, 'Jane Synth')
        assert c is not None
        assert c['action'] == 'suppress'
        assert c['reason'] == 'data_broker_wrong_person'

    def test_matching_person_slug_kept(self):
        c = _classify_serp_host('https://www.zoominfo.com/p/Jane-Synth/999',
                                [], [], self.TOKENS, 'Jane Synth')
        assert c is not None
        assert c['action'] == 'flag'
        assert c['category'] == 'DATA_BROKER_PII'

    def test_nickname_person_slug_matches(self):
        # mike ≈ michael: a rocketreach page for 'Mike Synth' matches VIP
        # 'Michael Synth'.
        c = _classify_serp_host('https://rocketreach.co/mike-synth-email',
                                [], [], self.TOKENS, 'Michael Synth')
        assert c is not None
        assert c['action'] == 'flag'
        assert c['category'] == 'DATA_BROKER_PII'

    def test_company_directory_page_kept(self):
        # A company-directory page (/c/) is brand-level, not per-person — kept
        # even though the slug is not a VIP name.
        c = _classify_serp_host('https://www.zoominfo.com/c/lumenfield-inc/456',
                                [], [], self.TOKENS, 'Jane Synth')
        assert c is not None
        assert c['action'] == 'flag'
        assert c['category'] == 'DATA_BROKER_PII'

    def test_no_vip_name_keeps_verdict(self):
        # Absent a VIP name to verify against, the data-broker verdict is kept
        # (no basis to disprove).
        c = _classify_serp_host('https://rocketreach.co/someone-else',
                                [], [], self.TOKENS, '')
        assert c is not None
        assert c['action'] == 'flag'

    def test_wrong_person_hit_dropped_end_to_end(self):
        hit = {'url': 'https://www.zoominfo.com/p/John-Doe/123',
               'title': 'John Doe', 'snippet': 'email', '_cohort': 'data_broker'}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', 'Lumenfield',
                                 'lumenfield.test', [], [], self.TOKENS)
        assert f is None


class TestDeterministicCohort:
    """#3 — emitted metadata.cohort is derived from the host classifier
    (URL-stable), not the dork that surfaced the URL."""

    TOKENS = ['lumenfield']

    def test_data_broker_cohort_is_canonical_regardless_of_dork(self):
        # Same data-broker URL found by the EXEC dork must still carry the
        # canonical 'data_broker' cohort (deterministic by URL).
        via_exec = {'url': 'https://rocketreach.co/jane-synth', 'title': 'Jane Synth',
                    'snippet': 'x', '_cohort': 'exec'}
        via_broker = {'url': 'https://rocketreach.co/jane-synth', 'title': 'Jane Synth',
                      'snippet': 'x', '_cohort': 'data_broker'}
        f1 = _serp_hit_to_finding('vip-1', via_exec, 'Jane Synth', 'Lumenfield',
                                  'lumenfield.test', [], [], self.TOKENS)
        assert f1 is not None
        f2 = _serp_hit_to_finding('vip-1', via_broker, 'Jane Synth', 'Lumenfield',
                                  'lumenfield.test', [], [], self.TOKENS)
        assert f2 is not None
        assert f1['metadata']['cohort'] == 'data_broker'
        assert f2['metadata']['cohort'] == 'data_broker'
        # The surfacing dork is still recorded separately for provenance.
        assert f1['metadata']['dorkCohort'] == 'exec'
        assert f2['metadata']['dorkCohort'] == 'data_broker'

    def test_combosquat_cohort_canonical(self):
        hit = {'url': 'https://lumenfield-login.test/', 'title': 'Login',
               'snippet': 'x', '_cohort': 'exec'}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', 'Lumenfield',
                                 'lumenfield.test', [], [], self.TOKENS)
        assert f is not None
        assert f['metadata']['cohort'] == 'combosquat'
        assert f['severity'] == 'HIGH'  # combosquat HIGH not regressed

    def test_content_match_falls_back_to_dork_cohort(self):
        # No host signal → cohort falls back to the surfacing dork.
        hit = {'url': 'https://news.blog.test/jane', 'title': 'Jane Synth interview',
               'snippet': 'Jane Synth talks strategy', '_cohort': 'exec'}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', 'Lumenfield',
                                 'lumenfield.test', [], [], self.TOKENS)
        assert f is not None
        assert f['metadata']['cohort'] == 'exec'
