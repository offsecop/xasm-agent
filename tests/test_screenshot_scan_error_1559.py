"""#1559 — surface the REAL gowitness failure reason in the capture error.

gowitness exits 0 with ZERO output (no screenshot, no JSONL record, empty
stderr) when Chromium navigation itself fails (ERR_SSL_PROTOCOL_ERROR on a
TLS-broken host; ERR_BLOCKED_BY_CLIENT on the http fallback under chromedp).
The tool mislabeled every such run 'Screenshot file not found after capture',
making the permafail breaker column undiagnosable. The fix: pass
--log-scan-errors so gowitness logs `failed to witness target ... err="..."`
to stderr, and surface that reason (or the JSONL failed_reason when present)
as the per-target error — scheme-tagged and joined across the protocol
fallback so `TyposquatDomain.lastScreenshotError` states the genuine upstream
reason for BOTH candidates.

Fictitious .test hosts only.
"""
import asyncio

import pytest

import tools.brand_monitor_screenshot as bms
from tools.brand_monitor_screenshot import BrandMonitorScreenshotTool


GW_NAV_FAIL_STDERR = (
    '2026-07-23T20:00:00Z ERR failed to witness target '
    'url=https://lumenfield-lander.test '
    'err="could not navigate to target: page load error net::ERR_SSL_PROTOCOL_ERROR"\n'
)


# ---------------------------------------------------------------------------
# _extract_scan_error (pure)
# ---------------------------------------------------------------------------
def test_extract_scan_error_reads_err_payload_from_stderr():
    reason = BrandMonitorScreenshotTool._extract_scan_error(GW_NAV_FAIL_STDERR, None)
    assert reason == (
        'could not navigate to target: page load error net::ERR_SSL_PROTOCOL_ERROR'
    )


def test_extract_scan_error_prefers_structured_failed_reason():
    probe = {'failed': True, 'failed_reason': 'probe-level boom'}
    reason = BrandMonitorScreenshotTool._extract_scan_error(GW_NAV_FAIL_STDERR, probe)
    assert reason == 'probe-level boom'


def test_extract_scan_error_none_when_no_evidence():
    assert BrandMonitorScreenshotTool._extract_scan_error('', None) is None
    assert (
        BrandMonitorScreenshotTool._extract_scan_error('gowitness happy noise', None)
        is None
    )
    # A non-failed probe must not be treated as a failure reason.
    assert (
        BrandMonitorScreenshotTool._extract_scan_error(
            '', {'failed': False, 'failed_reason': None}
        )
        is None
    )


# ---------------------------------------------------------------------------
# _run_gowitness_once — zero-output navigation failure surfaces the reason
# ---------------------------------------------------------------------------
class _ZeroOutputProcess:
    """gowitness exits 0, writes nothing, logs the nav failure to stderr."""

    pid = 4242
    returncode = 0

    async def communicate(self):
        return b'', GW_NAV_FAIL_STDERR.encode()


@pytest.mark.asyncio
async def test_run_gowitness_once_reports_navigation_reason(monkeypatch, tmp_path):
    captured_argv = {}

    async def _fake_create(*args, **kwargs):
        captured_argv['argv'] = list(args)
        return _ZeroOutputProcess()

    monkeypatch.setattr(bms.asyncio, 'create_subprocess_exec', _fake_create)
    monkeypatch.setattr(bms, 'register_group', lambda proc: None)

    # Skip the real 1s settle sleep.
    real_sleep = asyncio.sleep

    async def _fast_sleep(delay):
        await real_sleep(0)

    monkeypatch.setattr(bms.asyncio, 'sleep', _fast_sleep)

    tool = BrandMonitorScreenshotTool()
    result = await tool._run_gowitness_once(
        url='https://lumenfield-lander.test',
        target_dir=str(tmp_path),
        url_hash='abc123def456',
        ua_suffix='',
        chrome_path=None,
        user_agent_string=None,
    )

    # The nav-failure class must be surfaced verbatim, not the generic string.
    assert result['ok'] is False
    assert result['error'] == (
        'could not navigate to target: page load error net::ERR_SSL_PROTOCOL_ERROR'
    )
    # And the invocation opts in to gowitness scan-error logging.
    assert '--log-scan-errors' in captured_argv['argv']


@pytest.mark.asyncio
async def test_run_gowitness_once_keeps_generic_error_without_evidence(
    monkeypatch, tmp_path
):
    class _SilentProcess:
        pid = 4242
        returncode = 0

        async def communicate(self):
            return b'', b''

    async def _fake_create(*args, **kwargs):
        return _SilentProcess()

    monkeypatch.setattr(bms.asyncio, 'create_subprocess_exec', _fake_create)
    monkeypatch.setattr(bms, 'register_group', lambda proc: None)

    real_sleep = asyncio.sleep

    async def _fast_sleep(delay):
        await real_sleep(0)

    monkeypatch.setattr(bms.asyncio, 'sleep', _fast_sleep)

    tool = BrandMonitorScreenshotTool()
    result = await tool._run_gowitness_once(
        url='https://lumenfield-lander.test',
        target_dir=str(tmp_path),
        url_hash='abc123def456',
        ua_suffix='',
        chrome_path=None,
        user_agent_string=None,
    )
    assert result['ok'] is False
    assert result['error'] == 'Screenshot file not found after capture'


# ---------------------------------------------------------------------------
# _capture_screenshot — scheme-tagged reasons joined across the protocol fallback
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_capture_error_joins_scheme_tagged_reasons(monkeypatch, tmp_path):
    async def _resolves(host):
        return 'resolves'

    async def _not_closed(url):
        return False

    per_scheme = {
        'https': 'could not navigate to target: page load error net::ERR_SSL_PROTOCOL_ERROR',
        'http': 'could not navigate to target: page load error net::ERR_BLOCKED_BY_CLIENT',
    }

    async def _fake_once(self, url, target_dir, url_hash, ua_suffix,
                         chrome_path, user_agent_string):
        scheme = url.split(':', 1)[0]
        return {'ok': False, 'error': per_scheme[scheme], 'log_text': ''}

    monkeypatch.setattr(
        BrandMonitorScreenshotTool, '_host_resolves', staticmethod(_resolves)
    )
    monkeypatch.setattr(
        BrandMonitorScreenshotTool, '_port_definitely_closed', staticmethod(_not_closed)
    )
    monkeypatch.setattr(BrandMonitorScreenshotTool, '_run_gowitness_once', _fake_once)

    tool = BrandMonitorScreenshotTool()
    result = await tool._capture_screenshot(
        url='https://lumenfield-lander.test',
        brand_monitor_id='bm1',
        typosquat_domain_id='ts1',
        output_dir=str(tmp_path),
    )

    assert result['success'] is False
    assert result['error'] == (
        'https: could not navigate to target: page load error net::ERR_SSL_PROTOCOL_ERROR; '
        'http: could not navigate to target: page load error net::ERR_BLOCKED_BY_CLIENT'
    )
