"""Agent-side Layer-A lock for Cavalier lease precedence (#1619).

The two Cavalier legs each take their own `checkout_provider('CAVALIER')`
lease — a scan costs 2 units. That is honest accounting for 2 upstream calls.
The defect was issuing both checkouts CONCURRENTLY from one `asyncio.gather`:
on a tenant with a single unit left the winner was nondeterministic, so the
higher-value POSTURE leg (#1604, the infostealer-compromise surface) could
lose to the urls leg and go `unswept_quota` for that cycle.

These locks assert the INVARIANT (posture is always first in line for a
scarce unit), not an example. They fail if the legs are put back into the
gather as two concurrent entries.

Fictitious brand only (sol.test).
"""

import asyncio
import os
import sys
from typing import cast

import aiohttp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.darkweb_monitor import DarkWebMonitorTool  # noqa: E402

DOMAIN = 'sol.test'
# The sequencer never touches the session (both legs are stubbed); cast keeps
# the production signature strict rather than widening it for a test.
NO_SESSION = cast(aiohttp.ClientSession, None)


def _tool():
    return DarkWebMonitorTool()


def test_posture_leg_completes_before_urls_leg_starts():
    """Ordering invariant: the urls leg must not begin until posture is done.

    Concurrent gather entries interleave (posture-start, urls-start, ...);
    sequencing yields a strict start/end/start/end order.
    """
    order = []
    tool = _tool()

    async def fake_posture(session, domain, agent=None):
        order.append('posture:start')
        await asyncio.sleep(0)  # yield — a concurrent runner would interleave here
        order.append('posture:end')
        return [{'source': 'CAVALIER', 'leg': 'posture'}]

    async def fake_urls(session, domain, agent=None):
        order.append('urls:start')
        await asyncio.sleep(0)
        order.append('urls:end')
        return [{'source': 'CAVALIER', 'leg': 'urls'}]

    tool._query_cavalier = fake_posture
    tool._query_cavalier_urls = fake_urls

    results = asyncio.run(tool._query_cavalier_sequenced(NO_SESSION, DOMAIN))

    assert order == [
        'posture:start',
        'posture:end',
        'urls:start',
        'urls:end',
    ], f'legs interleaved (concurrent checkout race): {order}'
    assert [r['leg'] for r in results] == ['posture', 'urls']


def test_scarce_unit_goes_to_posture_not_urls():
    """With exactly ONE unit available, posture must be the leg that gets it.

    Models the quota layer: the first checkout wins, the second raises and its
    leg degrades to an empty result. Under the old concurrent gather this
    outcome was a coin flip.
    """
    remaining = {'units': 1}
    tool = _tool()
    winner = []

    async def checkout(leg):
        if remaining['units'] <= 0:
            raise RuntimeError('QuotaExceeded')
        remaining['units'] -= 1
        winner.append(leg)

    async def fake_posture(session, domain, agent=None):
        try:
            await checkout('posture')
        except RuntimeError:
            return []
        return [{'leg': 'posture'}]

    async def fake_urls(session, domain, agent=None):
        try:
            await checkout('urls')
        except RuntimeError:
            return []
        return [{'leg': 'urls'}]

    tool._query_cavalier = fake_posture
    tool._query_cavalier_urls = fake_urls

    results = asyncio.run(tool._query_cavalier_sequenced(NO_SESSION, DOMAIN))

    assert winner == ['posture'], f'the scarce unit went to {winner}, not posture'
    assert [r['leg'] for r in results] == ['posture']


def test_posture_failure_does_not_suppress_urls_leg():
    """Isolation invariant: the legs were independent gather entries before,
    and must stay independent in effect. A raising posture leg must not stop
    the urls leg from running."""
    tool = _tool()

    async def boom(session, domain, agent=None):
        raise RuntimeError('upstream 500')

    async def fake_urls(session, domain, agent=None):
        return [{'leg': 'urls'}]

    tool._query_cavalier = boom
    tool._query_cavalier_urls = fake_urls

    results = asyncio.run(tool._query_cavalier_sequenced(NO_SESSION, DOMAIN))
    assert [r['leg'] for r in results] == ['urls']


def test_urls_failure_does_not_discard_posture_results():
    tool = _tool()

    async def fake_posture(session, domain, agent=None):
        return [{'leg': 'posture'}]

    async def boom(session, domain, agent=None):
        raise RuntimeError('upstream 500')

    tool._query_cavalier = fake_posture
    tool._query_cavalier_urls = boom

    results = asyncio.run(tool._query_cavalier_sequenced(NO_SESSION, DOMAIN))
    assert [r['leg'] for r in results] == ['posture']
