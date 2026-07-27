"""Caching a You.com result so a hundred apps do not re-pay for the same query.

The cache key is derived from the capability, the app, the query text and the
allowlist, so a change to ANY of those is a different entry. That matters for
correctness as much as cost: reusing a result computed under a different host
allowlist would mean serving candidates that were never validated against the
current policy.

Two behaviors are deliberate. A cached entry is returned only while it is inside its
TTL, since research about credential pages goes stale. And a per-key lock means that
when several runs want the same uncached query at once, one call is made and the rest
wait for it, rather than a hundred parallel runs each paying for the same request.

A cache read or write failure is never fatal: the layer falls back to computing the
value, because losing a cache is a cost problem while failing a run is an outage.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import threading
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, TypeVar

from ops.you_metrics import _metrics


class ResearchCache(Protocol):
    """Provider-neutral cache so identical app research does not re-spend credits."""

    def get(self, key: str) -> Mapping[str, object] | None: ...

    def put(self, key: str, value: Mapping[str, object], *, expires_at: datetime) -> None: ...


# --------------------------------------------------------------------------
# Cache helper (single-flight over the persistent cache)
# --------------------------------------------------------------------------
def cache_key(
    kind: Literal["you-search", "you-contents", "you-research", "operational-research"],
    *parts: str,
) -> str:
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]
    return f"{kind}:v2:{digest}"


_CacheT = TypeVar("_CacheT")


async def _cached(
    cache: ResearchCache | None,
    key: str,
    *,
    ttl: timedelta,
    deserialize: Callable[[Mapping[str, object]], _CacheT | None],
    serialize: Callable[[_CacheT], Mapping[str, object]],
    compute: Callable[[], Awaitable[_CacheT]],
) -> _CacheT:
    """Return a cached value or compute+store it, single-flighting concurrent
    identical requests via the cache's per-key lock (see research_cache.py)."""

    if cache is None:
        return await compute()

    metrics = _metrics()
    raw = cache.get(key)
    if raw is not None:
        value = deserialize(raw)
        if value is not None:
            if metrics is not None:
                metrics.research_cache_hits += 1
            return value

    lock = getattr(cache, "lock_for", None)
    acquired = lock(key) if callable(lock) else None
    if acquired is not None:
        # A per-key threading.Lock is the right single-flight primitive here (each
        # enrichment runs in its own thread + event loop), but acquiring it must
        # never block the loop while another thread awaits a provider call.
        await asyncio.to_thread(acquired.acquire)
    try:
        raw = cache.get(key)
        if raw is not None:
            value = deserialize(raw)
            if value is not None:
                if metrics is not None:
                    metrics.research_cache_hits += 1
                return value
        if metrics is not None:
            metrics.research_cache_misses += 1
        result = await compute()
        if result is not None:  # negative results (e.g. Research found nothing) are not cached
            with contextlib.suppress(Exception):
                cache.put(key, serialize(result), expires_at=datetime.now(UTC) + ttl)
        return result
    finally:
        if acquired is not None:
            acquired.release()


# --------------------------------------------------------------------------
# In-memory research cache (unit tests only; production uses SqliteResearchCache)
# --------------------------------------------------------------------------
class InMemoryResearchCache:
    """A process-local :class:`ResearchCache` for isolated unit tests. No secrets."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Mapping[str, object], datetime]] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def get(self, key: str) -> Mapping[str, object] | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if datetime.now(UTC) >= expires_at:
            del self._store[key]
            return None
        return value

    def put(self, key: str, value: Mapping[str, object], *, expires_at: datetime) -> None:
        self._store[key] = (dict(value), expires_at)

    def lock_for(self, key: str) -> threading.Lock:
        with self._guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._locks[key] = lock
            return lock
