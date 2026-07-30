"""Happy path for the SQLite lease store and run queue.

One walk through the lifecycle two workers share: worker A claims a run and
renews it, worker B is refused while that lease is live, the deadline passes and
B claims it with a higher fencing token, A's release is reported as a no-op that
leaves B's lease alone, and B's own release frees the run. Plus one enqueue and
one dequeue, so the queue is exercised end to end.

The clock is injected rather than slept through: expiry is a comparison against
stored text, so moving the clock is the same event a real TTL would produce.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ops.core.storage import OperationsStorage
from ops.onboarding.lease import format_deadline, parse_deadline
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue

RUN_ID = "run-lease-001"


class Clock:
    """A movable clock, so a lease can expire without waiting a minute."""

    def __init__(self) -> None:
        self.moment = datetime(2025, 3, 1, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "private" / "ops.db"
    OperationsStorage(path).create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Example App",
        app_slug="example-app",
    )
    return path


def test_lease_lifecycle_across_two_workers(db_path) -> None:
    clock = Clock()
    store = SQLiteLeaseStore(db_path, clock=clock)

    first = store.claim(run_id=RUN_ID, worker_id="worker-a", ttl_seconds=60)
    assert first is not None
    assert first.fencing_token == 1
    assert parse_deadline(first.deadline) == clock.moment + timedelta(seconds=60)

    clock.advance(20)
    renewed = store.renew(lease=first, ttl_seconds=60)
    assert renewed is not None
    assert renewed.fencing_token == 1
    assert parse_deadline(renewed.deadline) == clock.moment + timedelta(seconds=60)

    # A live lease is exclusive: the second worker is refused, not queued.
    assert store.claim(run_id=RUN_ID, worker_id="worker-b", ttl_seconds=60) is None
    assert store.expired(limit=5) == ()

    # Worker A stops renewing; once the deadline passes the run is claimable.
    clock.advance(61)
    assert store.expired(limit=5) == (RUN_ID,)
    second = store.claim(run_id=RUN_ID, worker_id="worker-b", ttl_seconds=60)
    assert second is not None
    assert second.fencing_token == 2

    # Worker A is fenced out: its renewal fails and its release changes nothing.
    assert store.renew(lease=renewed, ttl_seconds=60) is None
    assert store.release(lease=renewed) is False
    assert store.claim(run_id=RUN_ID, worker_id="worker-c", ttl_seconds=60) is None

    assert store.release(lease=second) is True
    third = store.claim(run_id=RUN_ID, worker_id="worker-c", ttl_seconds=60)
    assert third is not None
    assert third.fencing_token == 3


def test_queue_enqueue_and_dequeue(db_path) -> None:
    clock = Clock()
    queue = SQLiteRunQueue(db_path, clock=clock)

    queue.enqueue(run_id=RUN_ID)
    assert queue.dequeue_candidates(limit=5) == (RUN_ID,)

    # A deferral is the one verb that may push a ready time later.
    queue.defer(run_id=RUN_ID, not_before=format_deadline(clock.moment + timedelta(seconds=30)))
    assert queue.dequeue_candidates(limit=5) == ()

    clock.advance(31)
    assert queue.dequeue_candidates(limit=5) == (RUN_ID,)

    # And a queued run is claimable through the queue.
    store = SQLiteLeaseStore(db_path, clock=clock)
    claimed = store.claim_next(worker_id="worker-a", ttl_seconds=60)
    assert claimed is not None
    assert claimed.run_id == RUN_ID
