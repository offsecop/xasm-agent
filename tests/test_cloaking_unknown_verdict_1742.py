"""#1742 — a failed bot capture must not count as clean cloaking evidence.

`_detect_cloaking` used to return `{detected: False, score: 0.0}` when it could
not form a bot-vs-human pair (bot capture failed / timed out while the human
captures succeeded — gowitness has a 10s timeout, so this is common). That
false verdict was stamped onto the successful human results and ingestion
counted it as a CLEAN capture toward the #1733 latch's clear streak: three
flaky bot captures in a row could release a latched cloaking alert on a domain
that is still cloaking.

Locks:
- no successful bot capture → UNKNOWN verdict (`detected is None`) and the
  stamping loop OMITS `cloakingDetected` / `cloakingScore` entirely (the
  absent shape ingestion already skips);
- a formed pair below threshold still yields a real clean `False` (the latch
  release path stays reachable);
- a formed diverging pair still yields `True` (recall intact).

Fictitious brands (`lumenfield`) on `.test` domains only.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tools.brand_monitor_screenshot import BrandMonitorScreenshotTool  # noqa: E402


def _tool() -> BrandMonitorScreenshotTool:
    return BrandMonitorScreenshotTool()


def _human(**extra):
    r = {'success': True, 'filePath': 'h.png', 'fileHash': 'sha256:aaa',
         'userAgent': 'desktop', 'pageTitle': None, 'finalUrl': None}
    r.update(extra)
    return r


def _bot(**extra):
    r = {'success': True, 'filePath': 'b.png', 'fileHash': 'sha256:bbb',
         'userAgent': 'bot', 'pageTitle': None, 'finalUrl': None}
    r.update(extra)
    return r


class TestUnknownVerdictOnMissingPair:
    def test_failed_bot_capture_yields_unknown_not_clean(self):
        # Bot capture FAILED (timeout), humans succeeded — no pair, no verdict.
        results = [
            _human(),
            _human(userAgent='mobile', filePath='m.png', fileHash='sha256:ccc'),
            _bot(success=False, filePath=None, error='gowitness timed out'),
        ]
        out = _tool()._detect_cloaking(results)
        assert out['detected'] is None
        assert out['score'] is None

    def test_failed_human_captures_also_yield_unknown(self):
        results = [
            _human(success=False, filePath=None, error='timeout'),
            _bot(),
        ]
        out = _tool()._detect_cloaking(results)
        assert out['detected'] is None

    def test_stamping_loop_omits_fields_on_unknown_verdict(self):
        # Mirror the execute() stamping contract: unknown → keys ABSENT, so
        # ingestion's `cloakingDetected == null` skip never sees a verdict.
        tool = _tool()
        ua_results = [
            _human(),
            _bot(success=False, filePath=None, error='gowitness timed out'),
        ]
        cloaking = tool._detect_cloaking(ua_results)
        for result in ua_results:
            if cloaking['detected'] is not None:
                result['cloakingDetected'] = cloaking['detected']
                result['cloakingScore'] = cloaking['score']
        for result in ua_results:
            assert 'cloakingDetected' not in result
            assert 'cloakingScore' not in result


class TestFormedPairStillVerdicts:
    def test_successful_bot_below_threshold_is_a_real_clean_false(self):
        # Identical fileHashes → SHA sets intersect → max_distance stays 0 →
        # genuinely clean. This MUST stay `False` (not None): real clean
        # captures still feed the #1733 clear streak so the latch releases.
        results = [
            _human(fileHash='sha256:same'),
            _bot(fileHash='sha256:same'),
        ]
        out = _tool()._detect_cloaking(results)
        assert out['detected'] is False
        assert out['score'] == 0.0

    def test_diverging_pair_still_detects(self):
        results = [
            _human(finalUrl='https://lumenfield-decoy.test/'),
            _bot(finalUrl='https://lumenfield-phish.test/login'),
        ]
        out = _tool()._detect_cloaking(results)
        assert out['detected'] is True
