"""#1088 — phishing_kit:fingerprint must self-bound to the per-job budget.

The tool fanned out every target with an unbounded `asyncio.gather`, so a batch
with enough slow/unresponsive domains blew the 300s per-job watchdog, got
HARD-KILLED, and every completed probe was discarded (nothing ingested). These
tests prove the tool now finishes BELOW a soft deadline and returns the targets
that completed (partial result), cancelling the rest, instead of hanging.
"""
import asyncio
import os
import sys
import time
import unittest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
for d in (AGENT_DIR, os.path.join(AGENT_DIR, 'tools')):
    if d not in sys.path:
        sys.path.insert(0, d)

from tools.phishing_kit_fingerprint import (  # noqa: E402
    _soft_deadline,
    _gather_within_budget,
)


class TestSoftDeadline(unittest.TestCase):
    def test_headroom_and_clamps(self):
        # 85% of the budget when that leaves >20s headroom.
        self.assertEqual(_soft_deadline(300.0), 255.0)
        # budget-20 wins over 85% for mid budgets.
        self.assertEqual(_soft_deadline(100.0), 80.0)
        # Floored at 30s so a small budget never degenerates to a tiny window...
        self.assertEqual(_soft_deadline(40.0), 30.0)
        # ...but never exceeds the budget itself when the budget is very small.
        self.assertEqual(_soft_deadline(25.0), 25.0)


class TestGatherWithinBudget(unittest.IsolatedAsyncioTestCase):
    async def test_returns_completed_in_order_and_skips_the_slow_one(self):
        async def fast(v):
            return {'domain': v}

        async def slow():
            await asyncio.sleep(5)  # would blow a real watchdog
            return {'domain': 'slow'}

        tasks = [
            asyncio.ensure_future(fast('a')),
            asyncio.ensure_future(slow()),
            asyncio.ensure_future(fast('b')),
        ]
        t0 = time.time()
        results, skipped = await _gather_within_budget(tasks, soft_deadline=0.3)
        elapsed = time.time() - t0

        # Did NOT wait out the 5s slow task — bounded by the soft deadline.
        self.assertLess(elapsed, 2.0)
        self.assertEqual(skipped, 1)
        # Completed targets preserved in INPUT order; the slow one is excluded.
        self.assertEqual([r['domain'] for r in results], ['a', 'b'])

    async def test_all_complete_when_budget_is_generous(self):
        async def fast(v):
            return {'domain': v}

        tasks = [asyncio.ensure_future(fast(x)) for x in ('a', 'b', 'c')]
        results, skipped = await _gather_within_budget(tasks, soft_deadline=5.0)
        self.assertEqual(skipped, 0)
        self.assertEqual([r['domain'] for r in results], ['a', 'b', 'c'])

    async def test_a_task_that_raises_is_dropped_not_fatal(self):
        async def fast(v):
            return {'domain': v}

        async def boom():
            raise RuntimeError('probe blew up')

        tasks = [
            asyncio.ensure_future(fast('a')),
            asyncio.ensure_future(boom()),
        ]
        results, skipped = await _gather_within_budget(tasks, soft_deadline=5.0)
        # The raiser completed (with an exception) so it is not "skipped", but it
        # is dropped from results — the batch is NOT discarded.
        self.assertEqual(skipped, 0)
        self.assertEqual([r['domain'] for r in results], ['a'])

    async def test_empty_task_list(self):
        self.assertEqual(await _gather_within_budget([], 1.0), ([], 0))


if __name__ == '__main__':
    unittest.main()
