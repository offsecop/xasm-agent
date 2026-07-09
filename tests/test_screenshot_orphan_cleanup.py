"""Regression test for issue #490 / #571 — orphaned-Chromium cleanup on screenshot timeout.

When a gowitness screenshot times out, the agent used to SIGKILL only the
gowitness Go parent; the headless Chromium tree it spawned reparented to PID 1
and kept burning CPU (no init reaps a LIVE orphan; Cloud Run has no init at all).

These tests assert the screenshot tool's half of the #571 fix:
  (a) gowitness is launched with start_new_session=True (process-group leader),
  (b) on timeout the WHOLE process group is torn down via the shared
      lib.process_reaper.terminate_group (SIGTERM -> grace -> SIGKILL -> reap).

The name-broadened, age-keyed periodic reaper itself is covered by
test_process_reaper.py.
"""
import asyncio
import signal

import pytest

import tools.brand_monitor_screenshot as bms
from tools.brand_monitor_screenshot import BrandMonitorScreenshotTool
import lib.process_reaper as pr


class _HangingProcess:
    """Fake subprocess whose communicate() never returns (forces timeout)."""

    pid = 4242

    def __init__(self):
        self.waited = False

    async def communicate(self):
        await asyncio.Event().wait()  # never resolves

    async def wait(self):
        self.waited = True
        return -9


def _patch_group_kill(monkeypatch):
    """Monkeypatch the shared reaper's group-kill primitives; return the call log."""
    killpg_calls = []
    monkeypatch.setattr(pr.os, 'getpgid', lambda pid: pid)
    monkeypatch.setattr(pr.os, 'killpg', lambda pgid, sig: killpg_calls.append((pgid, sig)))

    _real_sleep = asyncio.sleep

    async def _instant_sleep(_seconds):
        # Collapse the teardown grace but STILL yield to the loop (a non-yielding
        # stub would starve any concurrent while-True: sleep loop).
        await _real_sleep(0)

    monkeypatch.setattr(pr.asyncio, 'sleep', _instant_sleep)
    return killpg_calls


@pytest.mark.asyncio
async def test_gowitness_launched_with_new_session_and_group_killed_on_timeout(
    monkeypatch, tmp_path
):
    captured_kwargs = {}
    fake_proc = _HangingProcess()

    async def _fake_create(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return fake_proc

    # Force the timeout branch deterministically rather than waiting 60s.
    async def _fake_wait_for(awaitable, timeout):
        # Close the un-awaited coroutine to avoid "never awaited" warnings.
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise asyncio.TimeoutError()

    killpg_calls = _patch_group_kill(monkeypatch)
    monkeypatch.setattr(bms.asyncio, 'create_subprocess_exec', _fake_create)
    monkeypatch.setattr(bms.asyncio, 'wait_for', _fake_wait_for)

    tool = BrandMonitorScreenshotTool()
    result = await tool._run_gowitness_once(
        url='http://lumenfield.test',
        target_dir=str(tmp_path),
        url_hash='abc123def456',
        ua_suffix='',
        chrome_path=None,
        user_agent_string=None,
    )

    # (a) launched as a process-group leader
    assert captured_kwargs.get('start_new_session') is True

    # (b) the whole group was torn down SIGTERM-then-SIGKILL and reaped
    assert killpg_calls == [
        (fake_proc.pid, signal.SIGTERM),
        (fake_proc.pid, signal.SIGKILL),
    ]
    assert fake_proc.waited is True

    # The capture is reported as a timeout failure.
    assert result['ok'] is False
    assert result['error'] == 'timeout'


@pytest.mark.asyncio
async def test_partial_output_deleted_on_timeout(monkeypatch, tmp_path):
    """A partial screenshot written before the kill is removed; prior files stay."""
    # Pre-existing dedup file (must survive) and a "partial" the run produced.
    prior = tmp_path / 'old_capture.jpeg'
    prior.write_bytes(b'old')

    fake_proc = _HangingProcess()

    async def _fake_create(*args, **kwargs):
        # Simulate gowitness writing a partial file before it hangs.
        (tmp_path / 'partial_new.jpeg').write_bytes(b'partial')
        return fake_proc

    async def _fake_wait_for(awaitable, timeout):
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise asyncio.TimeoutError()

    _patch_group_kill(monkeypatch)
    monkeypatch.setattr(bms.asyncio, 'create_subprocess_exec', _fake_create)
    monkeypatch.setattr(bms.asyncio, 'wait_for', _fake_wait_for)

    tool = BrandMonitorScreenshotTool()
    await tool._run_gowitness_once(
        url='http://lumenfield.test',
        target_dir=str(tmp_path),
        url_hash='abc123def456',
        ua_suffix='',
        chrome_path=None,
        user_agent_string=None,
    )

    assert prior.exists(), "pre-existing dedup file must not be deleted"
    assert not (tmp_path / 'partial_new.jpeg').exists(), "partial output must be removed"
