"""Regression test for issue #491 — per-job execution watchdog.

A wedged tool must NOT pin a concurrency slot forever. `execute_job` holds the
`_job_semaphore` for the entire tool run, so without a per-job timeout a single
hung tool (observed: brand_monitor:screenshot stuck RUNNING ~4.5h) permanently
consumes a slot until a manual restart.

These tests assert that when the tool coroutine hangs beyond
`job_execution_timeout`:
  1. the job is reported FAILED to the backend (complete_job called with
     success=False), and
  2. the semaphore slot is released, so a subsequent job can acquire it.

The Agent is built without running its heavy __init__ (which needs a full config
+ PluginLoader); only the attributes the execution path touches are populated,
and all network/IO methods are replaced with async stubs.
"""
import asyncio
import signal
from contextvars import ContextVar

import pytest

from agent_core_rest import Agent, JobExecutionState


def _make_agent(timeout):
    """Build a minimally-wired Agent for the execution path, no real __init__."""
    agent = Agent.__new__(Agent)

    agent.job_execution_timeout = timeout
    agent.max_concurrent_jobs = 1
    agent._job_semaphore = asyncio.Semaphore(agent.max_concurrent_jobs)
    agent._active_jobs = {}
    agent._current_execution_state = ContextVar('current_execution_state', default=None)

    # Calls made on the failure path — stub them all out.
    agent.flush_output_buffer = _async_noop
    agent.queue_result = _async_noop
    agent.acknowledge_findings = _async_true
    agent.cleanup_output_file = _async_noop
    agent.cleanup_queue_file = _async_noop
    # Heartbeat loop must be a real-ish coroutine that can be cancelled.
    agent.execution_heartbeat_loop = _heartbeat_forever

    # complete_job is the assertion target — record its calls.
    agent.complete_calls = []

    async def _complete_job(job_id, result, success, retry_count=0):
        agent.complete_calls.append({'success': success, 'result': result})
        return True

    agent.complete_job = _complete_job

    # plugin_loader.execute_tool hangs longer than the watchdog.
    class _HangingLoader:
        async def execute_tool(self, tool_name, parameters):
            await asyncio.sleep(timeout * 100)
            return {'success': True}

    agent.plugin_loader = _HangingLoader()
    return agent


async def _async_noop(*args, **kwargs):
    return None


async def _async_true(*args, **kwargs):
    return True


async def _heartbeat_forever(state):
    while True:
        await asyncio.sleep(3600)


def _job():
    return {
        'id': 'deadbeef-0000-0000-0000-000000000000',
        'toolName': 'brand_monitor:screenshot',
        'parameters': {},
        'retryCount': 0,
    }


@pytest.mark.asyncio
async def test_hung_tool_is_reported_failed_and_releases_slot():
    agent = _make_agent(timeout=0.1)

    # Sanity: the slot is free before we start.
    assert agent._job_semaphore.locked() is False

    # execute_job acquires the semaphore for the whole run; it must return
    # (not hang) shortly after the 0.1s watchdog fires.
    await asyncio.wait_for(agent.execute_job(_job()), timeout=5)

    # 1. The job was reported FAILED to the backend so it can be requeued.
    assert len(agent.complete_calls) == 1
    assert agent.complete_calls[0]['success'] is False
    # #521 — the failure result is a structured dict {success, error, rawOutput}.
    assert 'timeout' in agent.complete_calls[0]['result']['error'].lower()

    # 2. The slot was released — a second job can acquire it immediately.
    assert agent._job_semaphore.locked() is False
    acquired = agent._job_semaphore.acquire()
    await asyncio.wait_for(acquired, timeout=1)
    agent._job_semaphore.release()


@pytest.mark.asyncio
async def test_spawned_process_group_is_torn_down_before_slot_release(monkeypatch):
    """#571 — a hung tool's spawned process group is SIGKILLed on the watchdog
    timeout, and the teardown runs while the concurrency slot is still held."""
    import lib.process_reaper as pr

    agent = _make_agent(timeout=0.1)

    class _FakeProc:
        pid = 5555
        returncode = None  # still alive -> must be torn down

        async def wait(self):
            self.returncode = -9
            return -9

    # A wedged tool that first registers a spawned process group, then hangs.
    class _SpawningLoader:
        async def execute_tool(self, tool_name, parameters):
            pr.register_group(_FakeProc())
            await asyncio.sleep(100)
            return {'success': True}

    agent.plugin_loader = _SpawningLoader()

    killpg_calls = []
    monkeypatch.setattr(pr.os, 'getpgid', lambda pid: pid)
    # Record the semaphore-held state AT teardown time to prove ordering.
    monkeypatch.setattr(
        pr.os, 'killpg',
        lambda pgid, sig: killpg_calls.append((pgid, sig, agent._job_semaphore.locked())),
    )
    monkeypatch.setattr(pr.os, 'waitpid', lambda pid, flags: (pid, 0))

    # NB: do NOT monkeypatch asyncio.sleep — pr.asyncio is the global module, so
    # patching it would also collapse the tool's own `sleep(100)` and prevent the
    # timeout. The teardown's real ~2s SIGTERM grace is well within the wait_for.
    await asyncio.wait_for(agent.execute_job(_job()), timeout=8)

    # The whole group was torn down SIGTERM-then-SIGKILL...
    assert [(p, s) for p, s, _ in killpg_calls] == [
        (5555, signal.SIGTERM),
        (5555, signal.SIGKILL),
    ]
    # ...while the slot was still held (teardown fires before the slot frees).
    assert all(locked is True for _, _, locked in killpg_calls)
    # ...and the slot is released afterwards.
    assert agent._job_semaphore.locked() is False
    assert agent.complete_calls[0]['success'] is False


@pytest.mark.asyncio
async def test_second_job_can_run_after_a_hung_job():
    """With a single slot, a second job must still be servable after a timeout."""
    agent = _make_agent(timeout=0.1)

    await asyncio.wait_for(agent.execute_job(_job()), timeout=5)

    # Swap in a fast, succeeding tool and run a second job through the same slot.
    class _FastLoader:
        async def execute_tool(self, tool_name, parameters):
            return {'success': True}

    agent.plugin_loader = _FastLoader()
    job2 = _job()
    job2['id'] = 'cafef00d-0000-0000-0000-000000000000'

    await asyncio.wait_for(agent.execute_job(job2), timeout=5)

    # Two completions total; the second one succeeded.
    assert len(agent.complete_calls) == 2
    assert agent.complete_calls[1]['success'] is True
