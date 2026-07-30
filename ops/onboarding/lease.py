"""Lease, fencing, and durable-queue types for the onboarding phase driver.

A run is driven by exactly one worker at a time, and "exactly one" has to survive
a crash, a container replacement, and a paused process that wakes up believing it
still owns the run. Two mechanisms carry that weight, and both of them are
properties of the :class:`Lease` value defined here.

The fencing token proves ownership; the deadline only makes ownership claimable.
    A lease carries a monotonic per-run :attr:`Lease.fencing_token` that the store
    increments on every successful claim (Requirement 16.3). A worker whose token
    no longer matches the stored one was fenced out — some other worker claimed
    the run after this lease expired — and it learns that from a renewal returning
    ``None``, not from the clock. The deadline is what makes an abandoned run
    claimable by someone else (Requirement 16.8); it is never treated as proof
    that the previous holder is dead. That is why the deadline is **absolute**
    rather than a duration: a duration would have to be interpreted against
    whichever clock read it, while an absolute deadline is a fact two workers can
    compare, and expiry is then a comparison rather than a countdown.

The deadline's text form is fixed-width on purpose.
    Deadlines cross the boundary as ISO-8601 UTC text because the store compares
    them as SQLite ``TEXT`` (``deadline < ?``), and that comparison is only a
    correct chronological order while every value has the same shape. The repo's
    usual ``datetime.now(UTC).isoformat()`` convention omits the fractional part
    when it happens to be zero, and ``"…:00Z" > "…:00.5Z"`` lexicographically — a
    once-in-a-million write that would order a deadline backwards. So this module
    owns one canonical form, always six fractional digits, produced by
    :func:`format_deadline` and enforced by :data:`DEADLINE_PATTERN`.

Relationship to ``Settings``, stated so the two cannot silently disagree.
    :data:`LEASE_TTL` and :data:`LEASE_RENEW_INTERVAL` are the *code-level
    defaults* — the numbers design LL-4.1 names, and the values a caller with no
    ``Settings`` in hand uses. The *runtime* source of both is
    ``ops.core.config.Settings.onboarding_lease_ttl_seconds`` and
    ``onboarding_lease_renew_interval_seconds``, whose bounds and one-third
    relationship a model validator enforces at startup. A caller that holds a
    ``Settings`` should build its timings with
    :meth:`LeaseTimings.from_settings` rather than reading the constants;
    ``tests/test_onboarding_lease_types.py`` pins the constants equal to the
    ``Settings`` defaults, so a change to one that is not mirrored in the other
    fails a test instead of producing two disagreeing budgets.

Scope: this module holds the lease vocabulary and the two ports. The SQLite
lease store and queue (task 9.2), the driver's renewal and fencing guard (task
9.3), and the lease-mechanics tests (task 9.4) are not sketched in advance. Both
ports exist so that replacing the SQLite-backed implementations with a shared
transactional store and a shared queue is a wiring change at the composition root
rather than an edit to the driver (Requirement 21.6).

Deployment constraint, stated next to the store it constrains. While the
SQLite-backed lease store and queue are the configured implementations, the
deployment runs onboarding workers on exactly 1 host: SQLite bounds writers to a
single host, and the fencing token above coordinates workers only through that
one store (Requirement 21.7). Multi-host worker scale-out requires the
shared-store and shared-queue port swap and is absent from the current
implementation (Requirement 21.8).
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, Protocol

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    # Deliberately typing-only: this is a vocabulary module, and the phase driver
    # imports it, so it stays free of the settings/pydantic import chain at
    # runtime. ``from_settings`` needs only attribute access.
    from ops.core.config import Settings

# Seconds a claim stays valid without renewal. The code-level default behind
# ``Settings.onboarding_lease_ttl_seconds`` (default 60, bounds 15..600).
LEASE_TTL: Final = 60

# Renewal cadence: one third of the TTL, so two consecutive renewals may fail
# while the deadline is still in the future (Requirement 16.7) and the driver can
# treat that as a transient store error rather than as being fenced out. The
# code-level default behind ``Settings.onboarding_lease_renew_interval_seconds``
# (default 20, bounds 5..200); the Settings model validator keeps the configured
# pair inside the same one-third relationship this pair satisfies.
LEASE_RENEW_INTERVAL: Final = 20

# Inclusive-lower, exclusive-upper bounds in seconds for the delay a worker waits
# before attempting a claim. Workers that wake on the same interval would
# otherwise contend on the same ``BEGIN IMMEDIATE`` every cycle, so all but one
# would see a busy store rather than a free run.
LEASE_CLAIM_JITTER: Final[tuple[float, float]] = (0.0, 2.0)

# The one canonical deadline form: ISO-8601 UTC, ``Z``-suffixed, always six
# fractional digits. Fixed width is the point — see the module docstring.
DEADLINE_PATTERN: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_DEADLINE_FORMAT: Final = "%Y-%m-%dT%H:%M:%S.%f"

# The bound the phase-history store puts on a run identifier, restated rather
# than imported: the driver imports this module, so importing the driver back
# would close a cycle.
MAX_IDENTIFIER_LENGTH: Final = 200


def format_deadline(moment: datetime) -> str:
    """Render an aware datetime as the canonical deadline text.

    A naive datetime is refused rather than assumed to be UTC: the deadline is
    written by one worker and read by another, so an unstated offset is a bug
    worth surfacing at the write.
    """

    if moment.tzinfo is None:
        raise ValueError("a lease deadline requires an aware datetime")
    return moment.astimezone(UTC).strftime(_DEADLINE_FORMAT) + "Z"


def parse_deadline(value: str) -> datetime:
    """Read a canonical deadline back as an aware UTC datetime."""

    if not DEADLINE_PATTERN.match(value):
        raise ValueError("a lease deadline must be ISO-8601 UTC with microseconds")
    return datetime.strptime(value.removesuffix("Z"), _DEADLINE_FORMAT).replace(tzinfo=UTC)


def deadline_after(ttl_seconds: int, *, now: datetime | None = None) -> str:
    """The canonical deadline text ``ttl_seconds`` from ``now``.

    The claiming worker's own clock sets the deadline, which is why
    :data:`LEASE_TTL` is an order of magnitude larger than realistic skew between
    workers.
    """

    if ttl_seconds < 1:
        raise ValueError("lease ttl must be at least one second")
    return format_deadline((now or datetime.now(UTC)) + timedelta(seconds=ttl_seconds))


def claim_jitter_seconds() -> float:
    """A delay drawn from :data:`LEASE_CLAIM_JITTER` to spread claim attempts.

    Scheduling jitter, not a secret: an observer learning this value gains
    nothing, and ownership is decided by the store's atomic claim regardless.
    """

    low, high = LEASE_CLAIM_JITTER
    return low + (high - low) * random.random()


@dataclass(frozen=True, slots=True)
class LeaseTimings:
    """The TTL and renewal cadence one driver run uses, checked against each other.

    Bundled because the two numbers are only correct as a pair: Requirement 16.7
    holds while the renewal cadence is at most a third of the TTL, so a caller
    that overrides one has to be stopped from silently invalidating the other.
    """

    ttl_seconds: int = LEASE_TTL
    renew_interval_seconds: int = LEASE_RENEW_INTERVAL

    def __post_init__(self) -> None:
        if self.ttl_seconds < 1 or self.renew_interval_seconds < 1:
            raise ValueError("lease timings must be at least one second")
        if self.renew_interval_seconds * 3 > self.ttl_seconds:
            raise ValueError("lease renew interval must be at most one third of the lease ttl")

    @classmethod
    def from_settings(cls, settings: Settings) -> LeaseTimings:
        """Timings as the deployment configured them.

        This is the constructor a caller holding a ``Settings`` should use; the
        module constants are the fallback for callers that have none.
        """

        return cls(
            ttl_seconds=settings.onboarding_lease_ttl_seconds,
            renew_interval_seconds=settings.onboarding_lease_renew_interval_seconds,
        )


# The timings a caller without a ``Settings`` uses. Equal to the ``Settings``
# defaults by test, not by coincidence.
DEFAULT_LEASE_TIMINGS: Final = LeaseTimings()


@dataclass(frozen=True, slots=True)
class Lease:
    """Exclusive, fenced, time-bounded ownership of one run.

    The four fields are the whole ownership proof: *which* run, *which* worker,
    the token that decides whether that worker still owns it, and the absolute
    instant after which someone else may take it.
    """

    run_id: str
    worker_id: str
    # Monotonic per run; the store increments it on every successful claim
    # (Requirement 16.3). The durable column defaults to 0 for a never-claimed
    # run, so a lease that exists always carries at least 1.
    fencing_token: int
    # Absolute ISO-8601 UTC instant in the canonical form above — never a
    # duration, so two workers can compare it without sharing a clock reading.
    deadline: str

    def __post_init__(self) -> None:
        _identifier(self.run_id, field="run id")
        _identifier(self.worker_id, field="worker id")
        if self.fencing_token < 1:
            raise ValueError("a lease carries a fencing token of at least one")
        # Raises for any non-canonical form, so every Lease in memory can be
        # compared against a stored deadline as text.
        parse_deadline(self.deadline)

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """Whether the deadline has passed, making the run claimable by another.

        Expiry is not evidence that this worker lost the run — only a renewal
        returning ``None`` proves that. It is evidence that another worker is
        *allowed* to claim it, which is why the driver stops before its next
        effect rather than after its deadline.
        """

        return (now or datetime.now(UTC)) >= parse_deadline(self.deadline)


class LeaseStore(Protocol):
    """Exclusive per-run ownership, fenced by a monotonic token.

    SQLite-backed today; reached through this port so a shared transactional
    store is a wiring change at the composition root (Requirement 21.6).
    """

    def claim(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> Lease | None:
        """Atomically acquire the run's exclusive lease, or ``None`` if it is held.

        PRE:  ``ttl_seconds >= 1``; ``run_id`` and ``worker_id`` are bounded
              identifiers naming an existing run and a live worker.
        POST: at most one live lease exists per run at any instant, so two
              workers never both believe they own a run (Requirement 16.2). A
              returned lease carries the run's fencing token incremented by
              exactly 1 (Requirement 16.3) and a deadline ``ttl_seconds`` in the
              future. ``None`` means another worker holds a live lease and is a
              normal outcome, not an error — nothing is written in that case.
              A run whose deadline has passed is claimable (Requirement 16.8),
              and claiming it changes no phase, no profile digest, and no
              reserved effect.
        """

    def claim_next(self, *, worker_id: str, ttl_seconds: int) -> Lease | None:
        """Claim any runnable run that is unleased or expired, or ``None``.

        PRE:  ``ttl_seconds >= 1``.
        POST: as :meth:`claim`, for whichever run the store selected. Candidates
              are considered oldest deadline first, so a run abandoned longest
              ago is picked up first. ``None`` means no run was claimable.
        """

    def renew(self, *, lease: Lease, ttl_seconds: int) -> Lease | None:
        """Extend the deadline iff this fencing token still owns the run.

        PRE:  ``ttl_seconds >= 1``.
        POST: on success, a lease with the same run id, worker id, and fencing
              token, and a deadline ``ttl_seconds`` in the future. ``None`` means
              this worker was fenced out — the run was claimed by someone else —
              and the current lease is left untouched. The caller's obligation on
              ``None`` is to stop driving immediately and perform no further side
              effect (Requirement 16.6), which is what a fenced-out worker's
              silence is built on. A renewal attempted after the deadline passed
              succeeds only while no other worker has claimed the run, because
              ownership is decided by the token and not by the clock.
        """

    def release(self, *, lease: Lease) -> bool:
        """Release the run iff this lease still owns it.

        PRE:  none. Releasing is safe on every exit path, which is what lets the
              driver satisfy "release exactly once" (Requirement 16.13) from a
              ``finally`` block.
        POST: ``True`` when this lease owned the run and the run is now free.
              ``False`` reports a no-op: the lease was superseded, the current
              lease is left unchanged, and a slow worker therefore cannot free
              the run its successor is driving (Requirement 16.12). The boolean
              exists so that no-op is *reported* rather than only logged; a
              caller unwinding on an exit path may discard it.
        """

    def expired(self, *, limit: int) -> tuple[str, ...]:
        """Run ids whose lease deadline has passed — crash detection.

        PRE:  ``limit >= 1``.
        POST: at most ``limit`` run ids, earliest deadline first, each currently
              claimable. This is a read: it changes no lease, and an id it
              returns may be claimed by another worker before the caller acts.
        """


class RunQueue(Protocol):
    """Durable work queue for onboarding runs, with deferral.

    SQLite-backed today; reached through this port so a shared queue is a wiring
    change at the composition root (Requirement 21.6).
    """

    def enqueue(self, *, run_id: str, not_before: str | None = None) -> None:
        """Queue a run durably, ready at ``not_before`` (now when omitted).

        PRE:  ``not_before``, when given, is a canonical deadline-grammar
              timestamp (:func:`format_deadline`).
        POST: the run is queued exactly once — the queue is keyed by run id, so
              enqueueing an already-queued run leaves one row and never moves its
              ready time later. Work already due therefore cannot be postponed by
              a re-enqueue (Requirement 16.1).
        """

    def dequeue_candidates(self, *, limit: int) -> tuple[str, ...]:
        """Queued run ids that are ready to be driven, earliest ready first.

        PRE:  ``limit >= 1``.
        POST: at most ``limit`` ids, each queued with a ready time that has
              passed. This is a candidate *read*, not a reservation: exclusivity
              belongs to :meth:`LeaseStore.claim`, so two workers may observe the
              same candidate and at most one of them will claim it. A candidate
              stays queued until the run is terminal, so a worker that dies
              between this read and its claim loses no work (Requirements 16.1,
              16.14).
        """

    def defer(self, *, run_id: str, not_before: str) -> None:
        """Re-queue a run with a delay — verification backoff and CAPTCHA waits.

        PRE:  ``not_before`` is a canonical deadline-grammar timestamp.
        POST: the run is queued with its ready time set to ``not_before``, and
              its committed phase is unchanged — a deferral is a scheduling fact,
              never a phase transition. This is the only verb that may move a
              ready time later, which is the whole point of it. A run that is not
              currently queued is enqueued.
        """


def _identifier(value: str, *, field: str, limit: int = MAX_IDENTIFIER_LENGTH) -> str:
    """Accept a bounded, single-line identifier and reject anything else.

    Mirrors the phase-history store's check, because a lease and a phase boundary
    name the same run and must agree on what a run id may look like.
    """

    if not value or len(value) > limit:
        raise ValueError(f"{field} is invalid")
    if any(character.isspace() or not character.isprintable() for character in value):
        raise ValueError(f"{field} is invalid")
    return value


__all__ = [
    "DEADLINE_PATTERN",
    "DEFAULT_LEASE_TIMINGS",
    "LEASE_CLAIM_JITTER",
    "LEASE_RENEW_INTERVAL",
    "LEASE_TTL",
    "MAX_IDENTIFIER_LENGTH",
    "Lease",
    "LeaseStore",
    "LeaseTimings",
    "RunQueue",
    "claim_jitter_seconds",
    "deadline_after",
    "format_deadline",
    "parse_deadline",
]
