"""Shared in-process async DNS resolver (dnspython) for agent tools.

Replaces per-lookup ``dig`` subprocesses (one ``fork()``+``execve()`` per query)
with async socket queries on the event loop. Resolving thousands of typosquat
candidates the old way spawned 4-8 ``dig`` processes per candidate; at scan
concurrency that exhausted the container PID cgroup ceiling (``pids.max``) and
produced ``Cannot fork`` / OCI-exec failures. Sockets, not processes, so the PID
ceiling is never touched.

Only the high-volume A/AAAA/NS/MX registration-probe path is migrated here; a
handful of enrichment probes (SPF/DMARC/DKIM TXT via ``dig``, curl) still fork,
but those run on the registered subset only, not per candidate.

UDP-first with a TCP fallback: some environments (a host DNS interceptor, or
Docker Desktop's embedded resolver behind one) silently DROP UDP/53 to the
configured upstreams while TCP/53 works. glibc honors resolv.conf
``options use-vc`` and uses TCP; ``dig``/UDP just time out. We mirror glibc by
retrying over TCP. To avoid paying the UDP-timeout penalty on every query in a
UDP-blocked env, we LATCH to TCP-only — but only after several CONSECUTIVE
UDP-fail-then-TCP-success observations (so a lone dropped packet in a healthy
env does NOT permanently degrade the whole process to TCP), and we periodically
re-probe UDP so a transient block that clears is picked back up.

Status strings mirror the legacy ``dig``-header rcode contract the callers rely
on: ``NOERROR`` (name exists; may or may not have records of this type),
``NXDOMAIN`` (name does not exist -> unregistered), ``SERVFAIL`` / ``TIMEOUT``
(could not determine -> registration UNKNOWN, must NOT be forced to unregistered).
"""
import asyncio
from typing import List, Tuple

import dns.asyncresolver
import dns.resolver
import dns.exception

# Bounded in-flight queries. 50 is safe on a small VM (sockets, not processes)
# and gentle on a single TCP upstream (avoids the many-simultaneous-TCP stall).
_MAX_INFLIGHT = 50
_CACHE_SIZE = 10000
_PER_SERVER_TIMEOUT = 3.0   # one server attempt
_TOTAL_LIFETIME = 6.0       # total budget for one resolve() call

_sem = None
_resolver = None
# UDP transport health. `_udp_ok` gates whether we attempt UDP first. We latch
# to TCP-only only after `_UDP_LATCH_STREAK` consecutive UDP-fail-then-TCP-success
# observations (a single UDP success resets the streak), so a lone dropped packet
# in a healthy env can't degrade the whole process. While latched we re-probe UDP
# every `_UDP_REPROBE_EVERY` queries so a transient block that clears is recovered.
_udp_ok = True
_udp_fail_streak = 0
_latched_query_count = 0
_UDP_LATCH_STREAK = 3
_UDP_REPROBE_EVERY = 500


def _get_sem() -> "asyncio.Semaphore":
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(_MAX_INFLIGHT)
    return _sem


def _get_resolver() -> "dns.asyncresolver.Resolver":
    global _resolver
    if _resolver is None:
        r = dns.asyncresolver.Resolver()
        r.cache = dns.resolver.LRUCache(_CACHE_SIZE)
        r.timeout = _PER_SERVER_TIMEOUT
        r.lifetime = _TOTAL_LIFETIME
        _resolver = r
    return _resolver


def _extract(rrset, rdt: str) -> List[str]:
    records: List[str] = []
    if rrset is None:
        return records
    for rd in rrset:
        if rdt in ('A', 'AAAA'):
            records.append(rd.address)
        elif rdt == 'NS':
            records.append(str(rd.target).rstrip('.').lower())
        elif rdt == 'MX':
            records.append(str(rd.exchange).rstrip('.').lower())
        else:
            records.append(rd.to_text())
    return records


async def resolve_records(domain: str, rrtype: str) -> Tuple[List[str], str]:
    """Resolve one record type. Returns ``(records, status)``. Never raises."""
    global _udp_ok, _udp_fail_streak, _latched_query_count
    rdt = rrtype.upper()
    resolver = _get_resolver()
    # While latched TCP-only, periodically re-probe UDP in case the block cleared.
    if not _udp_ok:
        _latched_query_count += 1
        if _latched_query_count >= _UDP_REPROBE_EVERY:
            _latched_query_count = 0
            _udp_ok = True
            _udp_fail_streak = 0
    attempts = (False, True) if _udp_ok else (True,)
    async with _get_sem():
        udp_failed = False
        for use_tcp in attempts:
            try:
                ans = await resolver.resolve(
                    domain, rdt, tcp=use_tcp, raise_on_no_answer=False,
                )
            except dns.resolver.NXDOMAIN:
                return [], 'NXDOMAIN'
            except dns.resolver.NoAnswer:
                # Name exists, no records of this type (NODATA) — definitive.
                return [], 'NOERROR'
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
                if not use_tcp:
                    udp_failed = True
                    continue
                return [], 'TIMEOUT'
            except dns.resolver.NoNameservers:
                # SERVFAIL from every server.
                if not use_tcp:
                    udp_failed = True
                    continue
                return [], 'SERVFAIL'
            except Exception:
                if not use_tcp:
                    udp_failed = True
                    continue
                return [], 'TIMEOUT'
            # Success (may be an empty rrset when raise_on_no_answer=False).
            if not use_tcp:
                # UDP worked — healthy. Reset the streak so an isolated earlier
                # UDP failure (packet loss) can never accumulate into a latch.
                _udp_fail_streak = 0
            elif udp_failed:
                # UDP failed then TCP succeeded — evidence this host blocks UDP.
                # Latch only after several consecutive such observations.
                _udp_fail_streak += 1
                if _udp_fail_streak >= _UDP_LATCH_STREAK:
                    _udp_ok = False
                    _latched_query_count = 0
            return _extract(getattr(ans, 'rrset', None), rdt), 'NOERROR'
        return [], 'TIMEOUT'
