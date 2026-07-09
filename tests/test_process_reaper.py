"""Unit tests for lib.process_reaper (#571).

Covers the three mechanisms:
  * the ContextVar registration seam (register_group / begin_job / end_job),
  * teardown_groups (SIGTERM -> grace -> SIGKILL of a job's spawned groups),
  * the periodic reaper reap_orphans — kills a genuine browser orphan (ppid==1,
    old enough, unprotected) and SKIPS every other case (live parent, young,
    protected group, non-matching name), and no-ops without /proc.
"""
import asyncio
import signal

import pytest

import lib.process_reaper as pr


# --------------------------------------------------------------------------- seam


class _FakeProc:
    """Minimal stand-in for an asyncio subprocess handle."""

    def __init__(self, pid, returncode=None):
        self.pid = pid
        self.returncode = returncode
        self.waited = False

    async def wait(self):
        self.waited = True
        self.returncode = -9
        return -9


def test_register_seam_appends_handles_and_noops_when_unbound():
    procs = []
    token = pr.begin_job(procs)
    p1 = _FakeProc(4242)
    pr.register_group(p1)
    pr.register_group(None)          # None -> ignored
    pr.register_group(_FakeProc(0))  # falsy pid -> ignored
    pr.end_job(token)
    # outside any bound job -> silent no-op
    pr.register_group(_FakeProc(9999))
    assert procs == [p1]


# --------------------------------------------------------------------------- teardown


@pytest.mark.asyncio
async def test_teardown_procs_sigterm_then_sigkill(monkeypatch):
    calls = []
    monkeypatch.setattr(pr.os, 'getpgid', lambda pid: pid)
    monkeypatch.setattr(pr.os, 'killpg', lambda pgid, sig: calls.append((pgid, sig)))

    proc = _FakeProc(101)
    killed = await pr.teardown_procs([proc], grace=0)
    assert killed == 1
    assert calls == [(101, signal.SIGTERM), (101, signal.SIGKILL)]
    assert proc.waited is True  # reaped


@pytest.mark.asyncio
async def test_teardown_skips_already_reaped_proc(monkeypatch):
    """The stale-pid-reuse guard: a finished (returncode set) handle is NOT signalled."""
    calls = []
    monkeypatch.setattr(pr.os, 'getpgid', lambda pid: pid)
    monkeypatch.setattr(pr.os, 'killpg', lambda pgid, sig: calls.append((pgid, sig)))

    assert await pr.teardown_procs([_FakeProc(101, returncode=0)], grace=0) == 0
    assert calls == []


@pytest.mark.asyncio
async def test_teardown_empty_is_noop(monkeypatch):
    calls = []
    monkeypatch.setattr(pr.os, 'killpg', lambda pgid, sig: calls.append((pgid, sig)))
    assert await pr.teardown_procs([]) == 0
    assert calls == []


def test_live_pgids_excludes_reaped(monkeypatch):
    monkeypatch.setattr(pr.os, 'getpgid', lambda pid: pid)
    alive, dead = _FakeProc(5), _FakeProc(6, returncode=0)
    assert pr.live_pgids([alive, dead]) == {5}


# --------------------------------------------------------------------------- reaper


def _write_proc(proc_root, pid, comm, ppid, starttime_ticks):
    pdir = proc_root / str(pid)
    pdir.mkdir()
    # /proc/<pid>/stat: pid (comm) state ppid ... starttime(field 22) ...
    # tail (after "(comm) ") is [state, ppid, <17 filler>, starttime]
    tail = "S {ppid} ".format(ppid=ppid) + "0 " * 17 + str(starttime_ticks)
    (pdir / 'stat').write_text(f"{pid} ({comm}) {tail}\n")


def _install_fake_proc(monkeypatch, tmp_path, uptime_seconds):
    proc_root = tmp_path / 'proc'
    proc_root.mkdir()
    (proc_root / 'uptime').write_text(f"{uptime_seconds} {uptime_seconds}\n")

    real_isdir = pr.os.path.isdir
    real_listdir = pr.os.listdir

    monkeypatch.setattr(pr.os.path, 'isdir', lambda p: True if p == '/proc' else real_isdir(p))
    monkeypatch.setattr(pr.os, 'listdir',
                        lambda p: real_listdir(str(proc_root)) if p == '/proc' else real_listdir(p))
    monkeypatch.setattr(pr.os, 'sysconf', lambda name: 100)  # clk_tck
    monkeypatch.setattr(pr.os, 'getpgid', lambda pid: pid)   # pgid == pid

    real_open = open

    def _open(path, *a, **k):
        if isinstance(path, str) and path.startswith('/proc/'):
            path = path.replace('/proc', str(proc_root), 1)
        return real_open(path, *a, **k)

    monkeypatch.setattr('builtins.open', _open)
    return proc_root


def test_reap_kills_only_the_genuine_unprotected_orphan(monkeypatch, tmp_path):
    uptime = 100_000.0
    old = 100          # etime ~= 100000 - 1 = 99999s  -> older than min_etime
    young = int((uptime - 10) * 100)  # etime ~= 10s   -> younger than min_etime

    _install_fake_proc(monkeypatch, tmp_path, uptime)
    proc_root = tmp_path / 'proc'
    # 101 chrome, orphan (ppid 1), old, unprotected            -> KILL
    _write_proc(proc_root, 101, 'chrome', 1, old)
    # 102 chromium, LIVE parent (ppid 99)                       -> SKIP (not orphan)
    _write_proc(proc_root, 102, 'chromium', 99, old)
    # 103 gowitness orphan but pgid protected                   -> SKIP (protected)
    _write_proc(proc_root, 103, 'gowitness', 1, old)
    # 104 python orphan (name not in REAP_NAMES)                -> SKIP (name)
    _write_proc(proc_root, 104, 'python3', 1, old)
    # 105 chromium orphan but too young                         -> SKIP (etime)
    _write_proc(proc_root, 105, 'chromium', 1, young)
    (proc_root / 'self').mkdir()  # non-numeric entry ignored

    killed = []
    monkeypatch.setattr(pr.os, 'kill', lambda pid, sig: killed.append((pid, sig)))

    count = pr.reap_orphans(protected_pgids={103}, min_etime=pr.DEFAULT_MIN_ETIME)

    assert count == 1
    assert killed == [(101, signal.SIGKILL)]


def test_reap_respects_dynamic_min_etime_for_long_jobs(monkeypatch, tmp_path):
    """A child of a long job (effective_timeout huge) is spared even at etime>330."""
    uptime = 100_000.0
    # etime ~= 500s: above the 330 default but a 3600s-timeout job's child is legit.
    starttime = int((uptime - 500) * 100)
    _install_fake_proc(monkeypatch, tmp_path, uptime)
    proc_root = tmp_path / 'proc'
    _write_proc(proc_root, 201, 'chromium', 1, starttime)

    killed = []
    monkeypatch.setattr(pr.os, 'kill', lambda pid, sig: killed.append((pid, sig)))

    # default threshold WOULD kill it...
    assert pr.reap_orphans(set(), min_etime=pr.DEFAULT_MIN_ETIME) == 1
    killed.clear()
    # ...but a raised threshold (a 3600s job is active) spares it.
    assert pr.reap_orphans(set(), min_etime=3600 + 60) == 0
    assert killed == []


def test_reap_noops_without_proc(monkeypatch):
    monkeypatch.setattr(pr.os.path, 'isdir', lambda p: False)
    assert pr.reap_orphans(set()) == 0
