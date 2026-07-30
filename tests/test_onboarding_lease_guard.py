"""Happy path for the driver-side renewal and fencing guard.

One walk through the case the guard exists for: worker A drives a run under a
lease, renewing on cadence, then stalls long enough for its deadline to pass and
for worker B to claim the run. A's next renewal reports the lost fencing token,
and from that point A performs no further step, releases exactly once, and leaves
B's lease exactly where it was.

The lease store is the real SQLite one — the fence is a property of its SQL, so a
double would be testing the double. Only `release` is wrapped, to count calls. The
clock is injected rather than slept through: expiry is a comparison against stored
text, so moving the clock is the same event a real TTL would produce.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ops.core.storage import OperationsStorage
from ops.onboarding.driver import LeaseGuard
from ops.onboarding.lease import LEASE_RENEW_INTERVAL, LEASE_TTL, Lease
from ops.onboarding.lease_store import SQLiteLeaseStore

RUN_ID = "run-guard-001"


class Clock:
    """A movable clock, so a lease can expire without waiting a minute."""

    def __init__(self) -> None:
        self.moment = datetime(2025, 3, 1, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)


class CountingLeaseStore(SQLiteLeaseStore):
    """The real store, plus a count of how many releases reached it."""

    releases = 0

    def release(self, *, lease: Lease) -> bool:
        self.releases += 1
        return super().release(lease=lease)


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


def test_lost_fencing_token_stops_driving_and_releases_once(db_path) -> None:
    clock = Clock()
    store = CountingLeaseStore(db_path, clock=clock)
    lease = store.claim(run_id=RUN_ID, worker_id="worker-a", ttl_seconds=LEASE_TTL)
    assert lease is not None

    steps: list[int] = []
    with LeaseGuard(store=store, lease=lease, clock=clock) as guard:
        for step in range(5):
            check = guard.before_step()
            if not check.may_drive:
                break
            assert check.lease is not None
            steps.append(step)
            clock.advance(LEASE_RENEW_INTERVAL)
            if step == 1:
                # Worker A stalls past its deadline and worker B takes the run.
                clock.advance(LEASE_TTL)
                stolen = store.claim(run_id=RUN_ID, worker_id="worker-b", ttl_seconds=LEASE_TTL)
                assert stolen is not None
                assert stolen.fencing_token > lease.fencing_token

    # Two steps ran, the third was refused, and nothing ran after the fence.
    assert steps == [0, 1]
    assert guard.status == "fenced"
    assert guard.before_step().may_drive is False

    # Released once, and that release was the reported no-op: worker B still owns
    # the run, so a third worker cannot claim it.
    assert store.releases == 1
    assert guard.release() is False
    assert store.releases == 1
    assert store.claim(run_id=RUN_ID, worker_id="worker-c", ttl_seconds=LEASE_TTL) is None
