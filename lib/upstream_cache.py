"""In-process TTL cache for socint upstream responses.

Per-process (5 agent containers = 5 independent caches). Acceptable trade-off:
no Redis in ASM infra (verified), and first-touch misses across the cluster
are <20 per typical workflow. See ASM integration map §7 for the storage
decision rationale.

RFC 5861 semantics (`stale-while-revalidate` / `stale-if-error`):

    fetched_at ────► expires_at ────► stale_until
                     (TTL ends)       (entry evicted)

- `get_fresh(key)` returns hits while `now < expires_at`.
- `get_stale(key)` returns hits while `now < stale_until` (used on upstream
  error fallback to honor `stale-if-error`).

Tenant-isolated by key prefix to defend against cross-tenant cache poisoning
(every key includes tenantId — see ASM integration map §6).

Ported from `social-media-monitoring/app/cache.py`. Single-file, no new deps.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """One row in the TTL cache.

    `fetched_at` is the UPSTREAM FETCH TIMESTAMP, not the cache-write time —
    callers pass an explicit value so HIT and MISS report identical
    `_meta.fetchedAt` to downstream consumers.
    """
    fetched_at: float        # unix seconds at upstream-fetch time
    expires_at: float        # past this, treat as stale
    stale_until: float       # past this, evict on access
    value: Any


class TTLCache:
    """Thread-safe-within-asyncio TTL cache with LRU eviction and a
    stale-grace window. All access serialized by a single `asyncio.Lock`."""

    def __init__(
        self,
        max_entries: int = 10_000,
        ttl_seconds: int = 900,
        stale_grace_seconds: int = 86_400,
    ) -> None:
        self._store: "OrderedDict[str, CacheEntry]" = OrderedDict()
        self._max = max_entries
        self._default_ttl = ttl_seconds
        self._default_stale_grace = max(0, stale_grace_seconds)
        self._lock = asyncio.Lock()
        # Counters for /cache-stats.
        self._hits = 0
        self._misses = 0
        self._stales = 0

    @staticmethod
    def make_key(
        tenant_id: Optional[str],
        namespace: str,
        method: str,
        url: str,
        params: Optional[dict] = None,
    ) -> str:
        """Build a canonical, tenant-scoped cache key.

        Tenant isolation is the FIRST key segment. A missing/None tenantId is
        REJECTED (raises) rather than bucketed into a shared "global" key — the
        old fallback let two tenant-less checkouts collide and read each other's
        cached payloads (V3). The sole caller bypasses the cache when tenantId is
        absent. Params are canonicalized via
        `json.dumps(sort_keys=True, separators=(",",":"))`.

        NEVER include the decrypted apiKey here — see CLAUDE.md "encryption
        boundary" rule. The lease's leaseToken is also excluded for the same
        reason.
        """
        canonical_params = json.dumps(
            params or {}, sort_keys=True, separators=(",", ":"), default=str,
        )
        if not tenant_id:
            raise ValueError("upstream_cache.make_key requires a tenant_id")
        return f"{tenant_id}|{namespace}|{method.upper()}|{url}|{canonical_params}"

    async def get_fresh(self, key: str) -> Optional[Tuple[Any, float]]:
        """Return `(value, fetched_at)` if the entry is still within TTL,
        else None. Evicts past stale_until."""
        if self._default_ttl <= 0:
            return None
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            now = time.time()
            if now >= entry.stale_until:
                self._store.pop(key, None)
                self._misses += 1
                return None
            if now >= entry.expires_at:
                # Expired but within grace — NOT "fresh". Caller can fall
                # back to get_stale on upstream error.
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            return entry.value, entry.fetched_at

    async def get_stale(self, key: str) -> Optional[Tuple[Any, float]]:
        """Return `(value, fetched_at)` for any non-evicted entry — fresh or
        stale. Use on the upstream-error fallback path to honor
        `stale-if-error`. Evicts past stale_until."""
        if self._default_ttl <= 0:
            return None
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            now = time.time()
            if now >= entry.stale_until:
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key)
            self._stales += 1
            return entry.value, entry.fetched_at

    async def set(
        self,
        key: str,
        value: Any,
        *,
        fetched_at: Optional[float] = None,
        ttl_seconds: Optional[int] = None,
        stale_grace_seconds: Optional[int] = None,
    ) -> None:
        """Write `value` under `key`.

        - `fetched_at`: defaults to now. Pass an explicit timestamp when the
          caller already recorded it elsewhere (e.g. immediately after the
          upstream response landed) so HIT-vs-MISS responses report
          identical `_meta.fetchedAt`.
        - `ttl_seconds`: overrides the cache-wide default for this entry
          only. Per-namespace TTLs (HikerAPI 5-min `fbsearch.accounts` vs
          1-h `user.by.username`) flow through this knob. `None` falls back
          to the cache-wide default. `<=0` skips the write entirely — used
          to disable caching for stub-mode without forking the call site.
        - `stale_grace_seconds`: overrides the cache-wide grace window for
          this entry only. `None` falls back to the cache-wide default.
        """
        effective_ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        if effective_ttl <= 0:
            return
        effective_grace = (
            stale_grace_seconds
            if stale_grace_seconds is not None
            else self._default_stale_grace
        )
        effective_grace = max(0, effective_grace)
        async with self._lock:
            ts = fetched_at if fetched_at is not None else time.time()
            self._store[key] = CacheEntry(
                fetched_at=ts,
                expires_at=ts + effective_ttl,
                stale_until=ts + effective_ttl + effective_grace,
                value=value,
            )
            self._store.move_to_end(key)
            while len(self._store) > self._max:
                self._store.popitem(last=False)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    async def stats(self) -> dict:
        """Snapshot counters for the /cache-stats endpoint. O(1)."""
        async with self._lock:
            return {
                "size": len(self._store),
                "max_entries": self._max,
                "default_ttl_seconds": self._default_ttl,
                "default_stale_grace_seconds": self._default_stale_grace,
                "hits": self._hits,
                "misses": self._misses,
                "stales": self._stales,
            }


# Module-level singleton — one cache per agent process. Five agent containers
# means five independent caches; tenant-scoped keys keep them safe.
upstream_cache = TTLCache()


# ---------------------------------------------------------------------------
# CachedResponse shim — minimal aiohttp.ClientResponse stand-in
# ---------------------------------------------------------------------------


class CachedResponse:
    """Tiny aiohttp.ClientResponse-shaped shim returned on cache hits.

    Vendor wrappers currently call `await resp.json()` and inspect
    `resp.status`. This shim provides exactly those two surfaces plus a
    no-op `release()` so wrappers don't need branchy `if cache_hit:` logic.

    We cache the PARSED JSON body (not the raw bytes / Response object) so
    repeated cache hits don't re-parse. `json()` is async to match aiohttp.
    """

    __slots__ = ("status", "_body", "headers")

    def __init__(self, status: int, body: Any, headers: Optional[dict] = None) -> None:
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def json(self) -> Any:  # noqa: D401 — mirror aiohttp signature
        return self._body

    async def text(self) -> str:
        try:
            return json.dumps(self._body)
        except (TypeError, ValueError):
            return str(self._body)

    async def release(self) -> None:
        return None
