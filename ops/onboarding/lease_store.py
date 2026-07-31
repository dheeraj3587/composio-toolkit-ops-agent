"""SQLite-backed lease store and run queue for the onboarding phase driver.

The ports and the lease vocabulary live in :mod:`ops.onboarding.lease`; the DDL
for the two tables lives in :mod:`ops.core.storage`, which owns every ``ops.db``
table. What lives here is the small amount of SQL that makes "exactly one worker
drives a run" true, and the reasons that SQL is shaped the way it is.

Ownership is decided by one statement, never by a read followed by a write.
    ``claim`` is a single upsert whose ``DO UPDATE`` carries the predicate
    ``holder IS NULL OR deadline < now``. A read-then-write would leave a window
    in which two workers both saw "free" and both wrote; the predicate has no
    such window, and the table's ``run_id`` primary key means a second live
    holder is unrepresentable rather than merely unlikely (Requirement 16.2).
    The same statement increments the run's fencing token, so a claim that
    succeeds always hands back a token exactly one higher than the previous
    holder's (Requirement 16.3) — there is no path that claims without
    incrementing.

A never-claimed run has no row, which is why the claim is an upsert.
    The token column defaults to 0, so the insert path writes token 1 and the
    conflict path writes ``fencing_token + 1``. Both arrive at "the first lease
    for a run carries at least 1", which is what :class:`Lease` asserts.

Renew and release share one predicate, and that predicate is the fence.
    Both match on ``run_id AND holder AND fencing_token``. A worker whose lease
    was superseded matches no row: its renewal returns ``None`` (it is fenced
    out and must stop before its next effect, Requirement 16.6) and its release
    returns ``False``, changing nothing — a slow worker therefore cannot free the
    run its successor is driving (Requirement 16.12). Neither verb consults the
    clock, because expiry is what makes a run *claimable*, not proof that the
    holder is gone.

Release keeps the token; only claim advances it.
    ``released_at`` and a NULL holder are what "free" looks like. The token stays
    where it is because it is monotonic per run, not per lease: resetting it on
    release would let a zombie's stale token match a future lease.

Deadlines are compared as text, so they are written in one canonical form.
    Every deadline and every queue ready-time goes through
    :func:`ops.onboarding.lease.format_deadline`, whose fixed-width output makes
    ``deadline < ?`` a correct chronological comparison in SQLite. The repo's
    usual ``isoformat()`` output is variable-width and would occasionally order a
    deadline backwards.

The queue's ready time can only move earlier, except through ``defer``.
    ``enqueue`` folds a repeat enqueue into ``MIN(existing, requested)``, so work
    already due cannot be postponed by a re-enqueue (Requirement 16.1).
    ``defer`` is the one verb allowed to push a ready time later, which is the
    whole point of it, and it touches no phase.

Both stores take an injectable clock. It is a test seam, not a policy: expiry
would otherwise only be reachable by sleeping through a real TTL.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from ops.core.private_files import finalize_private_database, prepare_private_database
from ops.core.storage import OperationsStorage
from ops.onboarding.lease import (
    MAX_IDENTIFIER_LENGTH,
    Lease,
    LeaseStore,
    RunQueue,
    deadline_after,
    format_deadline,
    parse_deadline,
)

# How many queue candidates ``claim_next`` inspects in one transaction before
# giving up. Bounded because the read happens under the write lock; the loop
# exists for the case where a candidate's lease is claimed between the read and
# the claim, which cannot happen within one ``BEGIN IMMEDIATE`` but is cheap to
# tolerate if this store is ever fronted by a shared transactional store.
CLAIM_CANDIDATE_LIMIT: Final = 20

_CLAIM_SQL: Final = """
INSERT INTO onboarding_leases (run_id, holder, fencing_token, deadline, claimed_at)
VALUES (?, ?, 1, ?, ?)
ON CONFLICT(run_id) DO UPDATE SET
    holder = excluded.holder,
    fencing_token = onboarding_leases.fencing_token + 1,
    deadline = excluded.deadline,
    claimed_at = excluded.claimed_at,
    released_at = NULL
WHERE onboarding_leases.holder IS NULL OR onboarding_leases.deadline < ?
"""

_CANDIDATE_SQL: Final = """
SELECT queued.run_id
FROM onboarding_queue AS queued
LEFT JOIN onboarding_leases AS held ON held.run_id = queued.run_id
WHERE queued.not_before <= ?
  AND (held.run_id IS NULL OR held.holder IS NULL OR held.deadline < ?)
ORDER BY COALESCE(held.deadline, queued.not_before) ASC
LIMIT ?
"""


class _LedgerDatabase:
    """Shared private-file, pragma, and transaction conventions for ``ops.db``."""

    def __init__(self, db_path: str | Path, *, clock: Callable[[], datetime] | None = None) -> None:
        self._path = Path(db_path)
        # ops/core/storage.py owns the DDL for every table these stores touch, so the
        # schema has exactly one owner.
        self._ledger = OperationsStorage(self._path)
        self._clock = clock or _utc_now
        self.initialize()

    def initialize(self) -> None:
        """Create the run-ledger schema if it is absent."""

        self._ledger.initialize()

    def _moment(self) -> datetime:
        moment = self._clock()
        if moment.tzinfo is None:
            raise ValueError("the lease clock must return an aware datetime")
        return moment.astimezone(UTC)

    def _now(self) -> str:
        """The current instant in the one form these tables compare as text."""

        return format_deadline(self._moment())

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """One immediate write transaction, committed or rolled back as a unit."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            connection.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        existed = prepare_private_database(self._path)
        connection = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        try:
            finalize_private_database(self._path, existed=existed)
            # A lease or a queue entry for a run that does not exist is a bug,
            # not a row to keep.
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA secure_delete = ON")
            yield connection
        finally:
            connection.close()


class SQLiteLeaseStore(_LedgerDatabase):
    """Exclusive, fenced per-run ownership in the run ledger."""

    def claim(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> Lease | None:
        """Acquire the run's lease, or ``None`` when another worker holds it."""

        run = _identifier(run_id, field="run id")
        worker = _identifier(worker_id, field="worker id")
        ttl = _ttl(ttl_seconds)
        with self._write() as connection:
            return self._claim(connection, run_id=run, worker_id=worker, ttl_seconds=ttl)

    def claim_next(self, *, worker_id: str, ttl_seconds: int) -> Lease | None:
        """Claim whichever queued run has been claimable longest, or ``None``."""

        worker = _identifier(worker_id, field="worker id")
        ttl = _ttl(ttl_seconds)
        now = self._now()
        with self._write() as connection:
            candidates = connection.execute(
                _CANDIDATE_SQL, (now, now, CLAIM_CANDIDATE_LIMIT)
            ).fetchall()
            for row in candidates:
                lease = self._claim(
                    connection, run_id=str(row[0]), worker_id=worker, ttl_seconds=ttl
                )
                if lease is not None:
                    return lease
        return None

    def _claim(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        worker_id: str,
        ttl_seconds: int,
    ) -> Lease | None:
        moment = self._moment()
        now = format_deadline(moment)
        deadline = deadline_after(ttl_seconds, now=moment)
        cursor = connection.execute(_CLAIM_SQL, (run_id, worker_id, deadline, now, now))
        if cursor.rowcount != 1:
            # A live lease is held by someone else. A normal outcome, and nothing
            # was written.
            return None
        row = connection.execute(
            "SELECT fencing_token, deadline FROM onboarding_leases WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:  # pragma: no cover - the upsert just wrote this row
            raise RuntimeError("claimed lease could not be read back")
        return Lease(
            run_id=run_id,
            worker_id=worker_id,
            fencing_token=int(row[0]),
            deadline=str(row[1]),
        )

    def renew(self, *, lease: Lease, ttl_seconds: int) -> Lease | None:
        """Push the deadline out iff this fencing token still owns the run."""

        ttl = _ttl(ttl_seconds)
        deadline = deadline_after(ttl, now=self._moment())
        with self._write() as connection:
            renewed = connection.execute(
                """
                UPDATE onboarding_leases
                SET deadline = ?
                WHERE run_id = ? AND holder = ? AND fencing_token = ?
                """,
                (deadline, lease.run_id, lease.worker_id, lease.fencing_token),
            ).rowcount
        if renewed != 1:
            # Fenced out: another worker claimed the run. Its lease is untouched.
            return None
        return Lease(
            run_id=lease.run_id,
            worker_id=lease.worker_id,
            fencing_token=lease.fencing_token,
            deadline=deadline,
        )

    def release(self, *, lease: Lease) -> bool:
        """Free the run iff this lease owns it; ``False`` reports a no-op."""

        with self._write() as connection:
            released = connection.execute(
                """
                UPDATE onboarding_leases
                SET holder = NULL, deadline = NULL, released_at = ?
                WHERE run_id = ? AND holder = ? AND fencing_token = ?
                """,
                (self._now(), lease.run_id, lease.worker_id, lease.fencing_token),
            ).rowcount
        return released == 1

    def holds(self, *, run_id: str) -> bool:
        """Whether a live (unexpired) lease owns the run right now.

        The complement of :meth:`expired` for one run: a holder whose deadline has
        passed is not proof that a worker is still driving it.
        """

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM onboarding_leases
                WHERE run_id = ? AND holder IS NOT NULL AND deadline >= ?
                """,
                (_identifier(run_id, field="run id"), self._now()),
            ).fetchone()
        return row is not None

    def expired(self, *, limit: int) -> tuple[str, ...]:
        """Run ids whose deadline has passed, earliest first — crash detection."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id
                FROM onboarding_leases
                WHERE holder IS NOT NULL AND deadline < ?
                ORDER BY deadline ASC
                LIMIT ?
                """,
                (self._now(), _limit(limit)),
            ).fetchall()
        return tuple(str(row[0]) for row in rows)


class SQLiteRunQueue(_LedgerDatabase):
    """The durable onboarding work queue, keyed by run id."""

    def enqueue(self, *, run_id: str, not_before: str | None = None) -> None:
        """Queue the run once, ready no later than it already was."""

        run = _identifier(run_id, field="run id")
        ready = self._now() if not_before is None else _timestamp(not_before)
        with self._write() as connection:
            connection.execute(
                """
                INSERT INTO onboarding_queue (run_id, not_before, enqueued_at)
                VALUES (?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    not_before = MIN(onboarding_queue.not_before, excluded.not_before)
                """,
                (run, ready, self._now()),
            )

    def dequeue_candidates(self, *, limit: int) -> tuple[str, ...]:
        """Queued run ids that are due, earliest ready first. A read, not a claim."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id
                FROM onboarding_queue
                WHERE not_before <= ?
                ORDER BY not_before ASC
                LIMIT ?
                """,
                (self._now(), _limit(limit)),
            ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def defer(self, *, run_id: str, not_before: str) -> None:
        """Move the run's ready time to ``not_before``; the phase is untouched."""

        run = _identifier(run_id, field="run id")
        ready = _timestamp(not_before)
        with self._write() as connection:
            connection.execute(
                """
                INSERT INTO onboarding_queue (run_id, not_before, enqueued_at)
                VALUES (?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET not_before = excluded.not_before
                """,
                (run, ready, self._now()),
            )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _identifier(value: str, *, field: str, limit: int = MAX_IDENTIFIER_LENGTH) -> str:
    """Accept a bounded, single-line identifier and reject anything else.

    Restated rather than imported so this module matches the phase-history store's
    boundary check on the same run id.
    """

    if not value or len(value) > limit:
        raise ValueError(f"{field} is invalid")
    if any(character.isspace() or not character.isprintable() for character in value):
        raise ValueError(f"{field} is invalid")
    return value


def _timestamp(value: str) -> str:
    """Keep a caller-supplied ready time inside the canonical deadline grammar."""

    parse_deadline(value)
    return value


def _ttl(value: int) -> int:
    if value < 1:
        raise ValueError("lease ttl must be at least one second")
    return value


def _limit(value: int) -> int:
    if value < 1:
        raise ValueError("limit must be at least one")
    return value


def _lease_store_conformance(store: SQLiteLeaseStore) -> LeaseStore:
    """Typecheck-only proof that the SQLite store satisfies its port."""

    return store


def _run_queue_conformance(queue: SQLiteRunQueue) -> RunQueue:
    """Typecheck-only proof that the SQLite queue satisfies its port."""

    return queue


__all__ = [
    "CLAIM_CANDIDATE_LIMIT",
    "SQLiteLeaseStore",
    "SQLiteRunQueue",
]
