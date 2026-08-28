"""#1508 — VIP-exposure SERP dorks: OPTIONAL recency window (default all-time).

The VIP dork sweep passed no `tbs` at all — every dork was implicitly
all-time, and re-scans kept re-surfacing decade-old hits with no way to
bound them. These locks pin the knob contract:

  * `window_days` UNSET/garbage/<1 → NO `tbs` reaches the dispatch —
    byte-identical all-time requests (today's behavior; a silent recall
    regression is the failure mode this guards against);
  * `window_days` set → the mapped `serper_tbs` value reaches the dispatch;
  * the effective window/tbs is surfaced in `searchDiagnostics.serp` so a
    scan record shows whether the sweep was bounded.

FICTITIOUS identity/brand only (Lumenfield / .test), per the synthetic-data
principle. All transport is mocked — no live calls, no real keys.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import tools.brand_monitor_vip_exposure as vip
from tools.brand_monitor_vip_exposure import BrandMonitorVipExposureTool


PARAMS = {
    'brandVipId': 'vip-1',
    'brandMonitorId': 'bm-1',
    'fullName': 'Avery Lumen',
    'companyName': 'Lumenfield',
    'companyDomain': 'lumenfield.test',
}


def _drive(monkeypatch, params):
    """Run execute() with the SERP sweep faked at execute_serp_queries,
    capturing every tbs the tool's dispatch closure passes down."""
    captured = {'tbs': [], 'dispatched': 0}

    async def fake_dispatch(query, page, session, timeout_seconds=None,
                            tbs=None, gl=None, empty_retry_budget=None):
        captured['tbs'].append(tbs)
        captured['dispatched'] += 1
        return {'hits': [], 'unswept': False}

    async def fake_execute(specs, agent=None, max_pages=30, _dispatch=None):
        assert _dispatch is not None
        await _dispatch('probe-dork', 1)
        return {
            'swept': True, 'status': 'swept', 'results': [],
            'diagnostics': {'pagesUsed': 1, 'queriesRun': 1,
                            'unsweptQueries': 0, 'truncated': False},
        }

    monkeypatch.setattr(vip, 'dispatch_serper', fake_dispatch)
    monkeypatch.setattr(vip, 'execute_serp_queries', fake_execute)
    monkeypatch.delenv('VIP_EXPOSURE_PUBLIC_SEARCH', raising=False)
    out = asyncio.run(BrandMonitorVipExposureTool().execute(params))
    return out, captured


class TestVipRecencyKnob:
    def test_default_is_all_time_no_tbs(self, monkeypatch):
        out, captured = _drive(monkeypatch, dict(PARAMS))
        assert out['success'] is True
        assert captured['dispatched'] >= 1
        assert captured['tbs'] == [None] * captured['dispatched']
        serp_diag = out['output']['searchDiagnostics']['serp']
        assert serp_diag['windowDays'] is None
        assert serp_diag['tbs'] is None

    def test_garbage_window_degrades_to_all_time(self, monkeypatch):
        for junk in ('{{ json searchWindowDays }}', 0, -3, 'soon'):
            out, captured = _drive(monkeypatch, dict(PARAMS, window_days=junk))
            assert out['success'] is True
            assert captured['tbs'] == [None] * captured['dispatched']

    def test_window_days_bounds_the_sweep(self, monkeypatch):
        out, captured = _drive(monkeypatch, dict(PARAMS, window_days=30))
        assert out['success'] is True
        assert captured['tbs'] == ['qdr:m'] * captured['dispatched']
        serp_diag = out['output']['searchDiagnostics']['serp']
        assert serp_diag['windowDays'] == 30
        assert serp_diag['tbs'] == 'qdr:m'

    def test_string_window_is_accepted(self, monkeypatch):
        # Templated knobs resolve to JSON numbers but arrive as strings on
        # manual runs — int-ish strings must work.
        out, captured = _drive(monkeypatch, dict(PARAMS, window_days='7'))
        assert captured['tbs'] == ['qdr:w'] * captured['dispatched']

    def test_schema_declares_the_optional_knob(self):
        schema = BrandMonitorVipExposureTool().schema
        assert 'window_days' in schema['properties']
        assert 'window_days' not in schema['required']


if __name__ == '__main__':
    pytest.main([__file__, '-q'])
