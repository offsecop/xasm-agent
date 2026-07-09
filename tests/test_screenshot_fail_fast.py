"""Fail-fast capture tests for issue #574.

A dead lookalike (no DNS, or no listener on 80/443) must short-circuit with ZERO
Chromium/gowitness launches, and a proven-dead host must never pay the
alternate-protocol retry. A reachable port still proceeds to gowitness, now with
the tightened --timeout/--delay flags.
"""
import asyncio

import pytest

import tools.brand_monitor_screenshot as bms
from tools.brand_monitor_screenshot import BrandMonitorScreenshotTool


def _spy_no_subprocess(monkeypatch):
    """Record any gowitness launch; the fail-fast paths must never spawn one."""
    created = []

    async def _fake_create(*args, **kwargs):
        created.append(args)
        raise AssertionError("gowitness/Chromium must NOT be launched for a dead host")

    monkeypatch.setattr(bms.asyncio, 'create_subprocess_exec', _fake_create)
    return created


@pytest.mark.asyncio
async def test_nxdomain_host_skips_browser_entirely(monkeypatch, tmp_path):
    async def _no_resolve(host):
        return 'nxdomain'  # #884 — tri-state: authoritative dead

    monkeypatch.setattr(BrandMonitorScreenshotTool, '_host_resolves', staticmethod(_no_resolve))
    created = _spy_no_subprocess(monkeypatch)

    tool = BrandMonitorScreenshotTool()
    result = await tool._capture_screenshot(
        url='http://does-not-resolve.test',
        brand_monitor_id='bm1',
        typosquat_domain_id='ts1',
        output_dir=str(tmp_path),
    )

    assert result['success'] is False
    assert 'DNS' in result['error']
    assert created == []  # zero Chromium


@pytest.mark.asyncio
async def test_refused_ports_run_gowitness_zero_times(monkeypatch, tmp_path):
    # Resolves, but both scheme ports actively REFUSE → both candidates skipped.
    async def _resolves(host):
        return 'resolves'  # #884 tri-state

    async def _refused(url):
        return True

    monkeypatch.setattr(BrandMonitorScreenshotTool, '_host_resolves', staticmethod(_resolves))
    monkeypatch.setattr(BrandMonitorScreenshotTool, '_port_definitely_closed', staticmethod(_refused))
    created = _spy_no_subprocess(monkeypatch)

    tool = BrandMonitorScreenshotTool()
    result = await tool._capture_screenshot(
        url='https://parked-no-listener.test',
        brand_monitor_id='bm1',
        typosquat_domain_id='ts1',
        output_dir=str(tmp_path),
    )

    assert result['success'] is False
    assert created == []  # neither the primary nor the alternate scheme launched


@pytest.mark.asyncio
async def test_open_port_proceeds_to_gowitness_with_tightened_flags(monkeypatch, tmp_path):
    async def _resolves(host):
        return 'resolves'  # #884 tri-state

    async def _not_closed(url):
        return False

    monkeypatch.setattr(BrandMonitorScreenshotTool, '_host_resolves', staticmethod(_resolves))
    monkeypatch.setattr(BrandMonitorScreenshotTool, '_port_definitely_closed', staticmethod(_not_closed))

    captured_cmd = {}

    class _HangingProcess:
        pid = 4242

        async def communicate(self):
            await asyncio.Event().wait()

        async def wait(self):
            return -9

    async def _fake_create(*args, **kwargs):
        captured_cmd['argv'] = list(args)
        return _HangingProcess()

    async def _fake_wait_for(awaitable, timeout):
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise asyncio.TimeoutError()

    async def _noop_terminate(proc, grace=2.0):
        return None

    monkeypatch.setattr(bms.asyncio, 'create_subprocess_exec', _fake_create)
    monkeypatch.setattr(bms.asyncio, 'wait_for', _fake_wait_for)
    monkeypatch.setattr(bms, 'terminate_group', _noop_terminate)

    tool = BrandMonitorScreenshotTool()
    await tool._capture_screenshot(
        url='http://live.test',
        brand_monitor_id='bm1',
        typosquat_domain_id='ts1',
        output_dir=str(tmp_path),
    )

    argv = captured_cmd.get('argv')
    assert argv, "gowitness should have launched for a reachable port"
    assert '--timeout' in argv and argv[argv.index('--timeout') + 1] == '10'
    assert '--delay' in argv and argv[argv.index('--delay') + 1] == '1'


@pytest.mark.asyncio
async def test_port_definitely_closed_only_on_refusal(monkeypatch):
    """A REFUSED port is definitively dead (skip); a TIMEOUT is ambiguous and must
    NOT be treated as closed (a slow/CDN-fronted live host must still get gowitness)."""
    async def _refuse(host, port):
        raise ConnectionRefusedError()

    async def _hang(host, port):
        await asyncio.Event().wait()

    async def _open(host, port):
        class _W:
            def close(self):
                pass

            async def wait_closed(self):
                pass
        return (object(), _W())

    monkeypatch.setattr(bms.asyncio, 'open_connection', _refuse)
    assert await BrandMonitorScreenshotTool._port_definitely_closed('https://x.test') is True

    monkeypatch.setattr(bms, 'PRECHECK_TIMEOUT', 0.05)
    monkeypatch.setattr(bms.asyncio, 'open_connection', _hang)
    assert await BrandMonitorScreenshotTool._port_definitely_closed('https://x.test') is False

    monkeypatch.setattr(bms.asyncio, 'open_connection', _open)
    assert await BrandMonitorScreenshotTool._port_definitely_closed('https://x.test') is False


# ---------------------------------------------------------------------------
# #884 — EAI_AGAIN (transient resolver) vs EAI_NONAME (authoritative NXDOMAIN).
# The pre-check must key on gaierror.errno: only a definitive dead name
# short-circuits; a transient resolver failure is 'ambiguous' and proceeds.
# ---------------------------------------------------------------------------
import socket


def _fake_loop_raising(exc):
    class _L:
        async def getaddrinfo(self, *a, **k):
            raise exc
    return _L()


@pytest.mark.asyncio
async def test_host_resolves_eai_again_is_ambiguous(monkeypatch):
    monkeypatch.setattr(
        bms.asyncio, 'get_event_loop',
        lambda: _fake_loop_raising(
            socket.gaierror(socket.EAI_AGAIN, 'Temporary failure in name resolution')),
    )
    assert await BrandMonitorScreenshotTool._host_resolves('flaky.test') == 'ambiguous'


@pytest.mark.asyncio
async def test_host_resolves_nxdomain_is_dead(monkeypatch):
    monkeypatch.setattr(
        bms.asyncio, 'get_event_loop',
        lambda: _fake_loop_raising(
            socket.gaierror(socket.EAI_NONAME, 'Name or service not known')),
    )
    assert await BrandMonitorScreenshotTool._host_resolves('nope.test') == 'nxdomain'


@pytest.mark.asyncio
async def test_host_resolves_timeout_is_ambiguous(monkeypatch):
    async def _slow_getaddrinfo(*a, **k):
        await asyncio.Event().wait()

    class _L:
        getaddrinfo = _slow_getaddrinfo

    monkeypatch.setattr(bms, 'PRECHECK_TIMEOUT', 0.02)
    monkeypatch.setattr(bms.asyncio, 'get_event_loop', lambda: _L())
    assert await BrandMonitorScreenshotTool._host_resolves('slow.test') == 'ambiguous'


@pytest.mark.asyncio
async def test_ambiguous_resolver_does_not_short_circuit_dead(monkeypatch, tmp_path):
    """A transient resolver failure (EAI_AGAIN) must NOT stamp the confident
    'host does not resolve (DNS)' verdict — the capture is ATTEMPTED. Here both
    ports then refuse, so we get a normal failed capture (NOT the DNS dead
    verdict that would drop a live registered lookalike from evidence)."""
    async def _ambiguous(host):
        return 'ambiguous'

    async def _refused(url):
        return True

    monkeypatch.setattr(BrandMonitorScreenshotTool, '_host_resolves', staticmethod(_ambiguous))
    monkeypatch.setattr(BrandMonitorScreenshotTool, '_port_definitely_closed', staticmethod(_refused))

    tool = BrandMonitorScreenshotTool()
    result = await tool._capture_screenshot(
        url='http://flaky-resolver.test',
        brand_monitor_id='bm1',
        typosquat_domain_id='ts1',
        output_dir=str(tmp_path),
    )
    assert result['success'] is False
    # The KEY assertion: NOT the authoritative dead verdict.
    assert result['error'] != 'host does not resolve (DNS)'


# ---------------------------------------------------------------------------
# #880 — parking / for-sale landing-page gate on the cloaking detector. A
# for-sale lander rotates ads per request so bot-vs-human captures diverge, but
# that is NOT cloaking: suppress the signal + mark the domain `parked`.
# ---------------------------------------------------------------------------
def _bot_human_diverging(**extra):
    # Distinct fileHashes, no pHash → SHA fallback → bot/human disjoint →
    # max_distance=1.0 → cloaking would fire (unless gated).
    human = {'success': True, 'filePath': 'h.png', 'fileHash': 'sha256:aaa',
             'userAgent': 'desktop', 'pageTitle': None, 'finalUrl': None}
    bot = {'success': True, 'filePath': 'b.png', 'fileHash': 'sha256:bbb',
           'userAgent': 'bot', 'pageTitle': None, 'finalUrl': None}
    human.update(extra.get('human', {}))
    bot.update(extra.get('bot', {}))
    return [human, bot]


def test_cloaking_recall_non_parking_divergence_still_fires():
    tool = BrandMonitorScreenshotTool()
    out = tool._detect_cloaking(_bot_human_diverging(
        human={'finalUrl': 'https://evil-decoy.test/'},
        bot={'finalUrl': 'https://evil-phish.test/login'},
    ))
    assert out['detected'] is True
    assert out['parked'] is False


def test_cloaking_suppressed_on_parking_title():
    tool = BrandMonitorScreenshotTool()
    out = tool._detect_cloaking(_bot_human_diverging(
        human={'pageTitle': 'This domain is for sale'},
    ))
    assert out['detected'] is False  # suppressed
    assert out['parked'] is True


def test_cloaking_suppressed_on_parking_host_final_url():
    tool = BrandMonitorScreenshotTool()
    out = tool._detect_cloaking(_bot_human_diverging(
        bot={'finalUrl': 'https://forsale.godaddy.com/?domain=x.test'},
    ))
    assert out['detected'] is False
    assert out['parked'] is True


def test_extract_final_url_prefers_explicit_then_last():
    tool = BrandMonitorScreenshotTool()
    assert tool._extract_final_url('status=200 final_url=https://forsale.godaddy.com/x more') \
        == 'https://forsale.godaddy.com/x'
    # no explicit field → last URL wins (gowitness logs the resolved URL).
    assert tool._extract_final_url('GET https://a.test then https://sedoparking.com/b') \
        == 'https://sedoparking.com/b'
    assert tool._extract_final_url('no urls here') is None
