"""Process-group teardown + orphan reaping shared across agent tools.

Generalizes the SIGKILL-on-timeout helper and the PID-1 chromium reaper that were
originally embedded in ``tools/brand_monitor_screenshot.py``. Two mechanisms, used
together:

1. **Immediate, job-attributed teardown.** A tool that spawns a CLI subprocess with
   ``start_new_session=True`` (making the child a process-group leader) calls
   :func:`register_group` with the child's pid. The per-job watchdog binds the current
   job's pgid set via :func:`begin_job` / :func:`end_job` and, on
   ``asyncio.TimeoutError`` / ``asyncio.CancelledError``, tears every registered group
   down (SIGTERM -> grace -> SIGKILL -> reap) **before** the concurrency slot is freed.
   The binding is a :class:`contextvars.ContextVar`, visible to tool code awaited on the
   same task. Procs spawned in a raw executor thread that did not inherit the context
   fall through to mechanism 2.

2. **Periodic reaper backstop.** Browser processes reparented to PID 1 are the only
   thing that leaks past mechanism 1 (Playwright launches Chromium inside the agent's own
   process group, so it cannot be ``killpg``'d without killing the agent — the tool closes
   it instead, and if that fails the browser reparents to init). Cloud Run has no init and
   the prod image does not set ``init: true``, so a live orphan is never collected. The
   reaper kills a process only when it is a genuine orphan (``ppid == 1``), matches a tight
   name set, is older than the longest active job could legitimately run, and is not part
   of any active job's registered group.
"""
from __future__ import annotations

import asyncio
import contextvars
import os
import signal

# Deliberately narrow: only the browser-orphan class actually reparents to PID 1 and
# burns cores for minutes. Short-lived CLI children (dig/whois/curl/openssl) are spawned
# start_new_session and torn down immediately by the watchdog, so a broad name list here
# would only add risk of reaping an unrelated same-named process. Matched as a substring
# of the lower-cased /proc/<pid>/comm.
REAP_NAMES: frozenset = frozenset({'chrome', 'chromium', 'gowitness'})

# Just above the 300s default per-job ceiling. The watchdog raises this dynamically to
# cover jobs whose configured timeoutSeconds exceeds the default (see the reaper loop in
# agent_core_rest.py), so a long job's live child is never mistaken for an orphan.
DEFAULT_MIN_ETIME = 330

_current_groups: contextvars.ContextVar = contextvars.ContextVar(
    'reaper_current_groups', default=None
)


# --------------------------------------------------------------------------- registration


def begin_job(proc_list: list) -> "contextvars.Token":
    """Bind ``proc_list`` as the current job's spawned-subprocess registry. Returns a token."""
    return _current_groups.set(proc_list)


def end_job(token: "contextvars.Token") -> None:
    """Unbind the current job's registry (call from the watchdog ``finally``)."""
    try:
        _current_groups.reset(token)
    except (ValueError, LookupError):
        pass


def register_group(proc) -> None:
    """Register a spawned subprocess (a process-group leader) with the current job.

    Stores the process HANDLE, not a bare pid, so teardown/reaper can consult its
    ``returncode``: an already-exited-and-reaped child is skipped, which eliminates
    the stale-pid-reuse hazard (killing a group whose pid the kernel recycled to an
    unrelated sibling job). No-op when called outside a bound job context (e.g. from a
    raw executor thread that did not inherit the ContextVar) — such procs are covered
    by the periodic reaper.
    """
    procs = _current_groups.get()
    if procs is not None and proc is not None and getattr(proc, 'pid', None):
        procs.append(proc)


def _proc_alive(proc) -> bool:
    """True if the process has not yet been reaped (returncode still None).

    A reaped child's pid may have been recycled by the kernel, so we must NOT signal
    it; a live or zombie (exited-but-unreaped) child still owns its pid, so signalling
    its group is safe.
    """
    return getattr(proc, 'returncode', None) is None


def _killpg_of(proc, sig: int) -> bool:
    pid = getattr(proc, 'pid', None)
    if not pid:
        return False
    return _killpg(pid, sig)


def live_pgids(procs) -> set:
    """Process-group ids of the still-alive registered procs (for reaper protection)."""
    pgids = set()
    for proc in list(procs or ()):
        if not _proc_alive(proc):
            continue
        pid = getattr(proc, 'pid', None)
        if not pid:
            continue
        try:
            pgids.add(os.getpgid(pid))
        except OSError:
            pgids.add(pid)
    return pgids


# --------------------------------------------------------------------------- kill helpers


def _killpg(pid: int, sig: int) -> bool:
    """Signal the whole group led by ``pid``. Guarded; returns True if a signal was sent."""
    try:
        os.killpg(os.getpgid(pid), sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False


def _reap(pid: int) -> None:
    try:
        os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, OSError):
        pass


async def terminate_group(process_or_pid, grace: float = 2.0) -> None:
    """SIGTERM the group led by the process, wait ``grace`` s, then SIGKILL, then reap.

    Accepts an ``asyncio`` subprocess object (preferred — it is awaited to reap) or a raw
    pid. Best-effort: an already-dead process never raises.
    """
    pid = getattr(process_or_pid, 'pid', process_or_pid)
    if not pid:
        return
    if _killpg(pid, signal.SIGTERM):
        try:
            await asyncio.sleep(grace)
        except asyncio.CancelledError:
            # Still escalate to SIGKILL even while being cancelled.
            pass
    _killpg(pid, signal.SIGKILL)
    if hasattr(process_or_pid, 'wait'):
        try:
            await process_or_pid.wait()
        except Exception:
            pass
    else:
        _reap(pid)


async def close_browser_safe(closable, timeout: float = 5.0) -> None:
    """Close a Playwright browser/context so it can never wedge the caller (#571).

    A hung ``browser.close()`` during a cancel/timeout unwind would hold the job's
    concurrency slot. ``shield`` keeps the close running to completion even while the
    task is being cancelled; ``wait_for`` caps it so a truly stuck driver is abandoned
    (the periodic reaper collects the reparented Chromium). Never raises.
    """
    if closable is None:
        return
    try:
        await asyncio.wait_for(asyncio.shield(closable.close()), timeout=timeout)
    except Exception:
        pass


async def teardown_procs(procs, grace: float = 2.0) -> int:
    """Tear down every still-alive registered subprocess group (SIGTERM -> grace ->
    SIGKILL -> reap). Already-reaped handles are skipped so a recycled pid is never
    signalled. Called by the watchdog under ``asyncio.shield`` from the job ``finally``,
    before the slot is freed. Returns the number of groups SIGKILLed.
    """
    alive = [p for p in (procs or ()) if _proc_alive(p)]
    if not alive:
        return 0
    for proc in alive:
        _killpg_of(proc, signal.SIGTERM)
    try:
        await asyncio.sleep(grace)
    except asyncio.CancelledError:
        pass
    killed = 0
    for proc in alive:
        if _killpg_of(proc, signal.SIGKILL):
            killed += 1
        try:
            await proc.wait()  # reap; frees the pid only now that it is dead
        except Exception:
            pass
    return killed


# --------------------------------------------------------------------------- reaper


def _read_stat(pid_entry: str):
    """Return (comm, ppid, starttime) from /proc/<pid>/stat, or raise."""
    with open(os.path.join('/proc', pid_entry, 'stat'), 'r') as fh:
        line = fh.read()
    # comm is parenthesized and may contain spaces/parens — split on the LAST ')'.
    rparen = line.rfind(')')
    comm = line[line.find('(') + 1:rparen]
    tail = line[rparen + 2:].split()  # tail[0]=state (field 3)
    ppid = int(tail[1])               # field 4
    starttime = int(tail[19])         # field 22 (clock ticks since boot)
    return comm, ppid, starttime


def reap_orphans(protected_pgids, *, min_etime: int = DEFAULT_MIN_ETIME,
                 names: frozenset = REAP_NAMES) -> int:
    """SIGKILL genuinely-orphaned (ppid==1) browser processes. Linux/``/proc`` only.

    A process is killed iff ALL hold: its comm matches ``names``; it is reparented to PID 1
    (parent dead — a live job's child has the agent/driver as parent, never 1); its elapsed
    time exceeds ``min_etime``; and its process group is not one of ``protected_pgids`` (the
    union of every active job's registered groups). No-op on non-Linux / no ``/proc``.
    """
    if not os.path.isdir('/proc'):
        return 0
    try:
        clk = os.sysconf('SC_CLK_TCK') or 100
    except (ValueError, OSError):
        clk = 100
    try:
        with open('/proc/uptime', 'r') as fh:
            uptime = float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        return 0
    protected = {int(p) for p in (protected_pgids or ()) if p}
    try:
        entries = os.listdir('/proc')
    except OSError:
        return 0

    killed = 0
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            comm, ppid, starttime = _read_stat(entry)
        except (OSError, ValueError, IndexError):
            continue
        if ppid != 1:
            continue
        name = comm.lower()
        if not any(n in name for n in names):
            continue
        etime = uptime - (starttime / clk)
        if etime < min_etime:
            continue
        pid = int(entry)
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = pid
        if pgid in protected:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            killed += 1
        except (ProcessLookupError, PermissionError):
            pass

    if killed:
        print(f"[ProcessReaper] Reaped {killed} orphaned process(es)")
    return killed
