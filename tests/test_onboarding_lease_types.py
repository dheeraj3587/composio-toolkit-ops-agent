"""Unit tests for the lease vocabulary's own invariants.

Lease *mechanics* — fencing-token monotonicity across claims, claim after expiry,
the superseded-release no-op, renewal past the deadline — belong to the store and
are covered once it exists. What is testable here is what the value type refuses
to represent: a lease with no owner, an unclaimed fencing token, a deadline in a
form the store could not compare, and a timings pair that would fence a live
worker out.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from ops.core.config import Settings
from ops.onboarding.lease import (
    DEFAULT_LEASE_TIMINGS,
    LEASE_CLAIM_JITTER,
    LEASE_RENEW_INTERVAL,
    LEASE_TTL,
    Lease,
    LeaseTimings,
    claim_jitter_seconds,
    deadline_after,
    format_deadline,
    parse_deadline,
)

NOW = datetime(2024, 5, 17, 12, 0, 0, tzinfo=UTC)
DEADLINE = format_deadline(NOW + timedelta(seconds=LEASE_TTL))


def lease(
    *,
    run_id: str = "run-001",
    worker_id: str = "worker-a",
    fencing_token: int = 7,
    deadline: str = DEADLINE,
) -> Lease:
    return Lease(
        run_id=run_id,
        worker_id=worker_id,
        fencing_token=fencing_token,
        deadline=deadline,
    )


def test_a_lease_carries_the_four_ownership_facts() -> None:
    held = lease()

    assert (held.run_id, held.worker_id, held.fencing_token) == ("run-001", "worker-a", 7)
    assert parse_deadline(held.deadline) == NOW + timedelta(seconds=LEASE_TTL)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", ""),
        ("run_id", "run 001"),
        ("worker_id", ""),
        ("worker_id", "worker\na"),
        # 0 is the durable column's never-claimed default, so it can never be the
        # token of a lease that exists.
        ("fencing_token", 0),
        ("fencing_token", -1),
    ],
)
def test_a_lease_refuses_an_owner_or_token_that_proves_nothing(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        lease(**{field: value})


@pytest.mark.parametrize(
    "deadline",
    [
        "2024-05-17T12:01:00+00:00",  # offset form, not Z
        "2024-05-17T12:01:00Z",  # no fractional part
        "2024-05-17T12:01:00.123Z",  # milliseconds, so not fixed width
        "2024-05-17 12:01:00.123456Z",  # space separator
        "not-a-timestamp",
        "",
    ],
)
def test_a_lease_refuses_a_deadline_the_store_could_not_compare(deadline: str) -> None:
    """Only the canonical fixed-width form is admitted.

    The store compares deadlines as SQLite TEXT, and mixed precision breaks that
    comparison, so the shape is refused at construction rather than producing a
    deadline that sorts backwards.
    """

    with pytest.raises(ValueError):
        lease(deadline=deadline)


def test_expiry_is_a_deadline_comparison() -> None:
    held = lease(deadline=format_deadline(NOW + timedelta(seconds=30)))

    assert held.is_expired(now=NOW) is False
    assert held.is_expired(now=NOW + timedelta(seconds=29)) is False
    assert held.is_expired(now=NOW + timedelta(seconds=30)) is True
    assert held.is_expired(now=NOW + timedelta(seconds=31)) is True


def test_the_canonical_deadline_text_orders_chronologically() -> None:
    """Fixed-width formatting is what keeps text order equal to time order.

    With the repo's usual ``isoformat`` convention the earlier of these two
    instants renders as ``...:00Z`` and the later as ``...:00.500000Z``, and
    ``"Z" > "."``, so the text comparison the store performs would order them
    backwards. Six fractional digits always is the fix.
    """

    earlier = NOW  # microsecond == 0, the case isoformat abbreviates
    later = NOW + timedelta(microseconds=500_000)

    assert format_deadline(earlier) == "2024-05-17T12:00:00.000000Z"
    assert format_deadline(earlier) < format_deadline(later)
    assert parse_deadline(format_deadline(later)) == later


def test_format_deadline_normalizes_to_utc_and_refuses_a_naive_datetime() -> None:
    offset_moment = datetime(2024, 5, 17, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))

    assert format_deadline(offset_moment) == "2024-05-17T12:00:00.000000Z"

    with pytest.raises(ValueError, match="aware"):
        format_deadline(datetime(2024, 5, 17, 12, 0, 0))


def test_deadline_after_sets_an_absolute_instant_and_bounds_the_ttl() -> None:
    assert deadline_after(LEASE_TTL, now=NOW) == format_deadline(NOW + timedelta(seconds=LEASE_TTL))

    with pytest.raises(ValueError):
        deadline_after(0, now=NOW)


def test_claim_jitter_stays_inside_its_declared_range() -> None:
    low, high = LEASE_CLAIM_JITTER
    draws = [claim_jitter_seconds() for _ in range(50)]

    assert all(low <= draw < high for draw in draws)


def test_lease_timings_reject_a_cadence_that_would_fence_a_live_worker_out() -> None:
    """Requirement 16.7 needs two renewals to be able to fail before the deadline."""

    assert LeaseTimings(ttl_seconds=120, renew_interval_seconds=40).renew_interval_seconds == 40

    with pytest.raises(ValueError, match="one third"):
        LeaseTimings(ttl_seconds=60, renew_interval_seconds=30)
    with pytest.raises(ValueError):
        LeaseTimings(ttl_seconds=0, renew_interval_seconds=0)


def test_the_code_level_defaults_agree_with_the_configured_defaults() -> None:
    """The constants and Settings are one budget, so they are pinned equal here.

    A caller holding a Settings sources its timings from it; a caller with none
    falls back to the constants. If those two disagreed, the same deployment would
    fence workers out on one path and not the other.
    """

    settings = Settings()

    assert LEASE_TTL == settings.onboarding_lease_ttl_seconds
    assert LEASE_RENEW_INTERVAL == settings.onboarding_lease_renew_interval_seconds
    assert LeaseTimings.from_settings(settings) == DEFAULT_LEASE_TIMINGS


def test_lease_timings_follow_a_tightened_configuration() -> None:
    settings = Settings.from_env(
        env={
            "ONBOARDING_LEASE_TTL_SECONDS": "120",
            "ONBOARDING_LEASE_RENEW_INTERVAL_SECONDS": "30",
        }
    )

    assert LeaseTimings.from_settings(settings) == LeaseTimings(
        ttl_seconds=120, renew_interval_seconds=30
    )
