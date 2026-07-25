"""Persistent SQLite cache for the You.com research layer.

Shared by Search, Contents, and Research so identical app research does not
re-spend credits. Two guarantees:

* **Persistence** — survives process restarts and new cache-object
  construction (a fresh ``SqliteResearchCache`` pointed at the same file sees
  prior rows). TTL-expired rows are treated as misses and deleted lazily.
* **Single-flight** — a per-key lock lets two concurrent identical requests
  collapse into ONE provider call: the first computes and stores, the second
  waits and reads the cached result.

The invocation model this is designed for: one enrichment runs in its own
thread via ``asyncio.run`` (its own event loop). Concurrency between identical
requests therefore happens across THREADS, so a ``threading.Lock`` per key is
the correct single-flight primitive. Within one enrichment's loop the same key
is never requested concurrently, so holding the per-key lock across an
``await`` cannot deadlock the loop.

NEVER cached: API keys, credentials, Authorization headers, private URLs,
OTPs, cookies, or raw provider bodies. Callers must only store already-
validated, bounded, public projections (EvidenceCandidate / EvidenceDocument
dumps, validated Research candidate lists).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

_MAX_PAYLOAD_BYTES = 512 * 1024  # bounded rows; a research projection is small

_SCHEMA = """
CREATE TABLE IF NOT EXISTS research_cache (
    cache_key   TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
"""


class SqliteResearchCache:
    """A thread-safe, WAL-mode SQLite implementation of the ResearchCache protocol."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + a coarse DB lock: connection may be used from
        # the worker threads that run per-enrichment event loops. The DB lock is
        # held only for the brief get/put, never across a provider await.
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._db_lock = threading.Lock()
        self._key_locks: dict[str, threading.Lock] = {}
        self._key_locks_guard = threading.Lock()

    def get(self, key: str) -> Mapping[str, object] | None:
        now = datetime.now(UTC).isoformat()
        with self._db_lock:
            row = self._conn.execute(
                "SELECT payload_json, expires_at FROM research_cache WHERE cache_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                return None
            payload_json, expires_at = row
            if expires_at <= now:
                self._conn.execute("DELETE FROM research_cache WHERE cache_key = ?", (key,))
                self._conn.commit()
                return None
        try:
            value = json.loads(payload_json)
        except (ValueError, TypeError):
            # A corrupt row is a miss; drop it so it is recomputed.
            with self._db_lock:
                self._conn.execute("DELETE FROM research_cache WHERE cache_key = ?", (key,))
                self._conn.commit()
            return None
        return value if isinstance(value, dict) else None

    def put(self, key: str, value: Mapping[str, object], *, expires_at: datetime) -> None:
        payload_json = json.dumps(dict(value), sort_keys=True)
        if len(payload_json.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
            # Never persist an unexpectedly large payload; skip caching instead.
            return
        now = datetime.now(UTC).isoformat()
        with self._db_lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO research_cache "
                "(cache_key, payload_json, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (key, payload_json, expires_at.astimezone(UTC).isoformat(), now),
            )
            self._conn.commit()

    def lock_for(self, key: str) -> threading.Lock:
        """Return a stable per-key lock for single-flight of the provider call."""

        with self._key_locks_guard:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key] = lock
            return lock

    def purge_expired(self) -> int:
        now = datetime.now(UTC).isoformat()
        with self._db_lock:
            cursor = self._conn.execute("DELETE FROM research_cache WHERE expires_at <= ?", (now,))
            self._conn.commit()
            return cursor.rowcount

    def close(self) -> None:
        with self._db_lock:
            self._conn.close()


__all__ = ["SqliteResearchCache"]
