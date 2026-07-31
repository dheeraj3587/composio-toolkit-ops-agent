"""The onboarding phase driver's durable phase-history port.

A run's phase is the value a worker resumes from after a crash, so it has to be
durable *before* the next phase's first side effect is reserved. This module owns
the port that makes it durable — :class:`PhaseHistoryStore` — and its SQLite
implementation over the existing run ledger (``ops.db``), whose DDL lives in
:mod:`ops.core.storage` so the file keeps a single schema owner.

Three properties are worth stating because they are the reason the code looks the
way it does.

Replay is a no-op enforced by the database, not by a pre-read.
    ``commit_phase`` computes the next sequence number and attempts the insert.
    Committing a boundary that was already committed violates the boundary
    uniqueness constraint, and that violation is swallowed as a ``False`` return
    carrying :data:`PHASE_REPLAY_NOOP`, with no row written and the run's current
    phase unchanged. A pre-read followed by an insert would leave a window where
    two workers both read "absent" and both wrote; the constraint has no such
    window. Only a *uniqueness* violation is swallowed — a foreign-key violation
    means the run does not exist, which is a bug and propagates.

``commit_phase`` validates the transition, not the caller's view of the world.
    The legality of ``from_phase -> to_phase`` is checked against
    :func:`ops.onboarding.phase.validate_phase_transition`, and an illegal pair
    raises :class:`ops.onboarding.phase.IllegalPhaseTransition` before anything is
    written. What is deliberately *not* checked is whether ``from_phase`` still
    equals the stored current phase: a replay by definition presents a stale
    ``from_phase``, and it must return ``False`` rather than raise.

The generation counter advances only when it is asked to.
    ``next_generation`` is the one call that increments the counter the credential
    operation key reads, so a retry that does not call it derives the same key and
    cannot mint a second credential. A caller that needs the current value without
    advancing it reads :meth:`SQLitePhaseHistoryStore.current_generation`.

A phase boundary and its effect reservation are one unit of work.
    ``commit_phase_with_reservation`` commits the boundary and reserves the
    target phase's operation key inside a single ``BEGIN IMMEDIATE``
    (Requirement 13.13). Two separate calls would leave a window in which a
    worker that lost its lease has committed a phase whose effect is unreserved,
    and the next claimant could reserve and submit while the first submission is
    still in flight. Inside one transaction the second claimant sees both rows or
    neither. Within that unit of work the phase is written first, so a crash can
    leave a phase with no reservation — safe, the next worker reserves it — but
    never a reservation with no phase.

An ambiguous outcome authorizes nothing, arithmetically.
    ``submission_count`` derives its answer from the unique reservation row:
    0 before any reservation, 0 after a provable failure, 1 once a submission has
    been handed out. ``mark_effect_reservation_outcome_unknown`` moves the row to
    a disposition that authorizes nothing and leaves that count at 1, so no path
    here can hand out a second submission for the same key (Requirement 13.10).

Renewal is the only proof of ownership; the clock is only a hint.
    :class:`LeaseGuard` is what the driver calls at the top of every iteration. A
    renewal returning ``None`` means this worker was fenced out, and the guard
    latches into a stopped state so no later call can hand the driver a lease to
    act under (Requirement 16.6). An expired deadline on its own is *not* that
    proof — it only makes the run claimable — so the guard answers an expiry by
    attempting the renewal that can settle the question, never by assuming the
    worst or the best.

The driver is the only component that commits a phase transition.
    ``drive_run`` claims the lease, reads the last committed phase, drives that
    phase (through the action loop for the browser-bearing phases, through a
    registered handler otherwise), maps the outcome onto one transition, and
    commits it. Handlers and the loop return a :class:`PhaseStep` and write
    nothing, so there is exactly one place a phase becomes durable
    (Requirements 12.9, 4.20). The one recovery the driver performs itself is the
    duplicate-account re-route: a signup the provider refused because the account
    already exists is committed as ``signup -> route_selected_login``, and the
    references signup stored before it submitted are adopted as the run's login
    references before that phase is driven, with no operator involved
    (Requirements 6.7, 6.8).

Scope: this module holds the phase-history port, the reserve-with-commit path,
the renewal/fencing guard, the driver itself, the two phases that are decisions
rather than page walks the generic loop can dispatch — email verification and
the developer application — and the CAPTCHA pause/resume path, which owns the one
boundary ``drive_run`` cannot commit because it stops at the pause.
"""

from __future__ import annotations

import logging
import random
import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, Self, cast, get_args

from pydantic import SecretStr

from ops.access.gate_policy import (
    HUMAN_ONLY_GATES,
    PROFILE_DECLARABLE_GATES,
    GateResolution,
    ProfileGateAuthority,
    resolve_gate,
)
from ops.browser.candidates import APPROVED_VALUE_REFS
from ops.browser.host_policy import BrowserAllowedHosts, evaluate_navigation
from ops.browser.metrics import OnboardingCorrelation
from ops.browser.worker import BrowserObservation, HumanActionType
from ops.core.effect_ledger import EffectStore
from ops.core.inference import DecisionFailed, DecisionReasonCode
from ops.core.model_input_dlp import sanitize_url
from ops.core.models import HitlRequest
from ops.core.private_files import finalize_private_database, prepare_private_database
from ops.core.storage import AUTONOMY_VERDICT_VALUES, OperationsStorage
from ops.email.verification import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    MAX_VERIFICATION_AGE_SECONDS,
    VERIFICATION_REQUEST_CLOCK_SKEW_SECONDS,
    VerificationPurpose,
    VerificationSecretKind,
    canonical_address,
    is_safe_verification_link,
    select_verification,
)
from ops.email.verification_provider import VerificationProvider, VerificationQuery
from ops.onboarding.action_loop import (
    CandidateDecider,
    LoopBudget,
    LoopObservation,
    LoopResult,
    LoopSession,
    LoopTelemetry,
    PhaseGoal,
    StepDeadlines,
    check_postconditions,
    run_action_loop,
)
from ops.onboarding.admission import (
    ADMISSION_GATE,
    ADMISSION_PROMPT_LIMIT,
    AdmissionDecision,
    admission_prompt,
)
from ops.onboarding.credentials import (
    CAPTURE_RECEIPT_DEVELOPER_APP_ID,
    TRANSIENT_LOGIN_KIND_PREFIX,
    TRANSIENT_LOGIN_VAULT_KINDS,
)
from ops.onboarding.effects import (
    EFFECT_PROVIDER,
    ONBOARDING_EFFECT_DISPOSITIONS,
    ONBOARDING_EFFECTS,
    EffectDisposition,
    EffectPlan,
    EffectRowStatus,
    OnboardingEffect,
    complete_effect,
    create_dev_app_key,
    mark_effect_outcome_unknown,
    plan_effect,
    plan_for_row_status,
)
from ops.onboarding.lease import (
    DEFAULT_LEASE_TIMINGS,
    Lease,
    LeaseStore,
    LeaseTimings,
    RunQueue,
)
from ops.onboarding.phase import (
    INITIAL_PHASE,
    ONBOARDING_PHASES,
    ONBOARDING_REASON_CODES,
    RESUMABLE_PHASES,
    SESSION_BEARING_PHASES,
    TERMINAL_PHASES,
    OnboardingPhase,
    OnboardingReasonCode,
    is_legal_phase_transition,
    legal_phase_targets,
    validate_phase_transition,
)
from ops.planner.decide import PlanOutcome
from ops.planner.plan import RunPlan
from ops.planner.store import RunPlanStore
from ops.planner.validator import (
    CREDENTIAL_SURFACE_ORDINAL,
    PLAN_REFUSAL_REASON_CODE,
    PlanRefusal,
    validate_plan,
)
from ops.providers.profile import (
    APPROVAL_REQUIREMENTS,
    BILLING_REQUIREMENTS,
    MAX_FLOW_STEPS,
    SOURCE_DIGEST_LENGTH,
    ApprovalRequirement,
    BillingRequirement,
    CredentialKind,
    FlowKind,
    FlowSpec,
    ProviderProfile,
)
from ops.providers.profile_store import ProviderProfileStore
from ops.recipes.app_recipes import AppRecipe, get_app_recipe

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    # Typing-only so the driver stays free of the settings/pydantic-settings
    # import chain at runtime; ``from_settings`` needs only attribute access.
    from ops.core.config import Settings

LOGGER = logging.getLogger("composio_ops.onboarding_driver")

# The reason code a swallowed replay reports. Named here so the ``False`` return
# of ``commit_phase`` and the code recorded for it cannot drift apart.
PHASE_REPLAY_NOOP: Final[OnboardingReasonCode] = "phase_replay_noop"

# A profile digest is a SHA-256 hex content address, the same width the profile
# module enforces on its own digests.
PROFILE_DIGEST_LENGTH: Final = SOURCE_DIGEST_LENGTH

# The bound ``api.models`` puts on a correlation identifier, applied here so a
# value that cannot be projected onto the API is refused at the write boundary
# rather than discovered when the timeline is rendered.
MAX_CORRELATION_ID_LENGTH: Final = 64
MAX_IDENTIFIER_LENGTH: Final = 200

# Effect name -> the durable counter its operation key reads. Only the credential
# path has a counter, because supersede is the only effect a run may legitimately
# perform twice; a second signup or a second developer application is never
# wanted, so neither has an escape hatch.
GENERATION_COUNTERS: Final[dict[str, str]] = {"generate_credential": "credential_generation"}

# The ``onboarding_run_state`` column the credential-validation ladder counts in.
# Named next to the generation counters because the two are read together by the
# one phase that owns both ladders (Requirements 10.15 through 10.19).
VALIDATION_COUNTER: Final = "validation_attempt"

# The ``onboarding_run_state`` column the verification ladder counts in. Durable
# for the same reason the validation counter is: a verification retry is a
# re-entry into ``email_verification`` by a possibly different worker, so a count
# held in a worker's memory would restart at zero and poll the mailbox forever
# (Requirements 7.19, 7.27, 7.28).
VERIFICATION_COUNTER: Final = "verification_attempt"

# The ``onboarding_run_state`` column the CAPTCHA pause budget counts in. Durable
# because a pause ends the worker's turn by definition: the count that decides
# whether a further prompt may be emitted (Requirement 11.11) has to be readable
# by the next worker, and by the resume path, which are never the process that
# incremented it.
CAPTCHA_PROMPT_COUNTER: Final = "captcha_prompts"

# The ``onboarding_run_state`` column the one pre-execution prompt counts in.
# Durable and next to the CAPTCHA counter because the two together are the whole
# of a run's operator-prompt accounting (Requirement 11.15), and because "has this
# run already asked?" has to be answerable by a worker that is not the one that
# asked (Requirement 11.13).
ADMISSION_PROMPT_COUNTER: Final = "admission_prompts"

# The only phase the admission prompt may be emitted in. Named here beside the
# counter it guards so the at-most-once write and the phase it is scoped to are
# read together (Requirement 11.13).
ADMISSION_PROMPT_PHASE: Final[OnboardingPhase] = "awaiting_admission"

# The ``side_effect_intents`` statuses under which the provider has already been
# handed one submission for the key. ``failed`` is absent because a failure is
# recorded only when the attempt provably did not reach the provider, and
# ``outcome_unknown`` is present because an ambiguous outcome must be counted as a
# submission — that is exactly what keeps a second one from being authorized
# (Requirements 13.10, 13.11).
SUBMITTED_STATUSES: Final[frozenset[str]] = frozenset({"pending", "completed", "outcome_unknown"})

# The ledger's four durable row statuses as data, so a stored value is read back
# through the same vocabulary the effect module classifies against.
EFFECT_ROW_STATUSES: Final[tuple[EffectRowStatus, ...]] = get_args(EffectRowStatus)

# The reason code an ambiguous effect carries, matching what the effect module
# returns for a reconcile so the two cannot disagree.
OUTCOME_UNKNOWN: Final[OnboardingReasonCode] = "outcome_unknown"

# SQLite extended result codes for the two constraints that make a replay a
# no-op. A foreign-key failure (787) is deliberately absent: it means the run does
# not exist, and swallowing it would hide the bug.
_SQLITE_CONSTRAINT_PRIMARYKEY: Final = 1555
_SQLITE_CONSTRAINT_UNIQUE: Final = 2067
_UNIQUE_VIOLATION_CODES: Final[frozenset[int]] = frozenset(
    {_SQLITE_CONSTRAINT_PRIMARYKEY, _SQLITE_CONSTRAINT_UNIQUE}
)

# Consecutive renewal *failures* — a store that raised, not a store that fenced
# us out — the driver tolerates before exiting (Requirement 16.7). Two is not a
# retry budget picked for comfort: the renewal cadence is at most one third of the
# TTL, so after two failures a third of the TTL still remains, which is the margin
# that lets the driver finish its current observation and unwind without ever
# acting under an unconfirmed lease.
MAX_RENEWAL_FAILURES: Final = 2

# What the guard tells the driver at the top of an iteration.
#   ``ok``                   -> the lease is confirmed live; drive the next step.
#   ``fenced``               -> a renewal returned ``None``. Another worker owns
#                               the run. Stop now, perform no further side effect,
#                               and leave the current (successor's) lease alone.
#   ``renewal_unconfirmed``  -> renewals keep failing with the deadline still in
#                               the future. Nothing is known to be lost, but
#                               ownership is unconfirmed, so finish the current
#                               observation, perform no side effect, and exit.
# Neither stop status carries an onboarding reason code, and that is deliberate: a
# worker in either state must not commit a phase, and a reason code exists only to
# be written onto a boundary.
LeaseGuardStatus = Literal["ok", "fenced", "renewal_unconfirmed"]


@dataclass(frozen=True, slots=True)
class PhaseTransition:
    """One committed phase boundary, exactly as it was recorded.

    Carries the six facts Requirement 12.12 requires of every transition — source
    phase, target phase, reason code, profile digest, attempt, correlation id —
    plus the gapless per-run sequence and the commit timestamp. Nothing here is
    free-form: every field is a closed vocabulary, a fixed-width digest, a bounded
    identifier, or an integer.
    """

    sequence: int
    from_phase: OnboardingPhase | None
    to_phase: OnboardingPhase
    reason_code: OnboardingReasonCode
    profile_digest: str
    attempt: int
    correlation_id: str
    committed_at: str


@dataclass(frozen=True, slots=True)
class EffectReservationRecord:
    """The durable onboarding view of one reserved operation key.

    ``disposition`` is the *standing* answer for the key rather than a history of
    answers: what a worker arriving now is authorized to do about it. ``receipt``
    is present only once the effect completed, and carries non-secret identifiers
    only.
    """

    run_id: str
    operation_key: str
    effect: OnboardingEffect
    generation: int
    phase: OnboardingPhase
    disposition: EffectDisposition
    receipt: dict[str, str] | None
    reason_code: OnboardingReasonCode


@dataclass(frozen=True, slots=True)
class ReservedPhaseCommit:
    """The result of committing a phase and reserving that phase's effect at once.

    ``committed`` is ``False`` for a replayed boundary. In that case nothing was
    written — no history row and no new reservation — and ``plan`` reports the
    disposition the durable ledger already records for the key, so a replaying
    worker learns what to do without reserving anything.
    """

    committed: bool
    plan: EffectPlan


@dataclass(frozen=True, slots=True)
class CaptchaPause:
    """The two durable facts a CAPTCHA pause leaves behind (design LL-3.6).

    ``phase_at_pause`` is the phase the run was driving when the challenge
    appeared, which is what a resume re-enters rather than restarting the walk;
    it is ``None`` for a run that has never paused. ``prompts`` is the run's
    CAPTCHA prompt count, and it is the value the pause budget is compared
    against — a count held in a worker's memory would restart at zero on the
    next claim and the budget would never be reached (Requirements 11.2, 11.3,
    11.11).

    Both are read back through the phase vocabulary rather than as free text, so
    a stored phase that is not a phase is refused at the read boundary.
    """

    phase_at_pause: OnboardingPhase | None
    prompts: int

    def __post_init__(self) -> None:
        if self.phase_at_pause is not None:
            _phase(self.phase_at_pause)
        if self.prompts < 0:
            raise ValueError("a captcha prompt count cannot be negative")


class PhaseHistoryStore(Protocol):
    """Durable phase boundaries and the counters the operation keys read."""

    def commit_phase(
        self,
        *,
        run_id: str,
        from_phase: OnboardingPhase | None,
        to_phase: OnboardingPhase,
        reason_code: OnboardingReasonCode,
        profile_digest: str,
        attempt: int,
        correlation_id: str,
    ) -> bool:
        """Durably record one phase boundary. Returns ``False`` for a replay.

        PRE:  ``to_phase`` is declared for ``from_phase`` in the legal transition
              table, or equals ``from_phase``; otherwise ``IllegalPhaseTransition``
              is raised and nothing is written.
        POST: the run's current phase equals ``to_phase``. A repeated identical
              transition returns ``False``, writes no row, and leaves the current
              phase unchanged.
        """

    def current_phase(self, *, run_id: str) -> tuple[OnboardingPhase, int] | None:
        """The last committed phase and its attempt counter, or ``None``."""

    def history(self, *, run_id: str) -> tuple[PhaseTransition, ...]:
        """Every committed boundary for the run, in commit order."""

    def next_generation(self, *, run_id: str, effect: str) -> int:
        """Advance and return the effect's generation counter.

        POST: increments ONLY when called, so a retry that does not call it reuses
              the current generation and therefore the current operation key.
        """

    def current_generation(self, *, run_id: str, effect: str) -> int:
        """The effect's current generation counter, without advancing it.

        This is the read a retry performs: it needs the generation the previous
        attempt used in order to derive the same operation key.
        """

    def next_validation_attempt(self, *, run_id: str) -> int:
        """Count this credential-validation attempt and return the new count.

        The counter the validation ladder terminates on (Requirements 10.15,
        10.16). It is durable rather than held in the phase because a retry is a
        re-entry into ``credential_validation`` by a possibly different worker: an
        in-memory count would restart at zero and retry forever.

        POST: increments by exactly one per call and never resets, so the budget
              bounds the run's validation attempts as a whole.
        """

    def next_verification_attempt(self, *, run_id: str) -> int:
        """Count this email-verification attempt and return the new count.

        The counter the verification ladder terminates on (Requirements 7.19,
        7.28), durable for the same reason the validation counter is: every
        deferral ends the worker's turn, so the count has to outlive it.

        POST: increments by exactly one per call and never resets, so the attempt
              budget bounds the run's mailbox reads as a whole rather than per
              worker.
        """

    def verification_attempts(self, *, run_id: str) -> int:
        """The run's consumed email-verification attempts, advancing nothing.

        The read half of :meth:`next_verification_attempt`, in the same shape
        :meth:`current_generation` is the read half of :meth:`next_generation`. The
        autonomy outcome reports the run's total rather than the walk's, so it has
        to come from the durable column instead of a worker's tally.
        """

    def validation_attempts(self, *, run_id: str) -> int:
        """The run's consumed credential-validation attempts, advancing nothing."""


class SQLitePhaseHistoryStore:
    """Phase history in the run ledger, with replay refused by a constraint."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        # ops/core/storage.py owns every ops.db table, including the two this store
        # reads and writes, so the file has exactly one DDL owner.
        self._ledger = OperationsStorage(self._path)
        self.initialize()

    def initialize(self) -> None:
        """Create the run-ledger schema if it is absent."""

        self._ledger.initialize()

    def commit_phase(
        self,
        *,
        run_id: str,
        from_phase: OnboardingPhase | None,
        to_phase: OnboardingPhase,
        reason_code: OnboardingReasonCode,
        profile_digest: str,
        attempt: int,
        correlation_id: str,
    ) -> bool:
        """Record one phase boundary durably; ``False`` means it was a replay."""

        run = _identifier(run_id, field="run id")
        code = _reason_code(reason_code)
        digest = _profile_digest(profile_digest)
        correlation = _identifier(
            correlation_id, field="correlation id", limit=MAX_CORRELATION_ID_LENGTH
        )
        attempt_number = _attempt(attempt)
        # Raises before the transaction opens, so a refused transition cannot
        # leave a partial write behind.
        validate_phase_transition(from_phase, to_phase, code)

        with self._write() as connection:
            return self._commit_phase(
                connection,
                run_id=run,
                from_phase=from_phase,
                to_phase=to_phase,
                reason_code=code,
                profile_digest=digest,
                attempt=attempt_number,
                correlation_id=correlation,
            )

    def _commit_phase(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        from_phase: OnboardingPhase | None,
        to_phase: OnboardingPhase,
        reason_code: OnboardingReasonCode,
        profile_digest: str,
        attempt: int,
        correlation_id: str,
    ) -> bool:
        """Commit one boundary on a caller-owned immediate transaction.

        Separated from :meth:`commit_phase` so the reservation path can later
        commit the phase and reserve the operation key in one unit of work, which
        is what keeps a concurrent claim from interleaving between the two.
        """

        now = _utc_now()
        sequence = self._next_sequence(connection, run_id)
        try:
            connection.execute(
                """
                INSERT INTO onboarding_phase_history (
                    run_id, sequence, from_phase, to_phase, reason_code,
                    profile_digest, attempt, correlation_id, committed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    sequence,
                    from_phase,
                    to_phase,
                    reason_code,
                    profile_digest,
                    attempt,
                    correlation_id,
                    now,
                ),
            )
        except sqlite3.IntegrityError as error:
            if not _is_unique_violation(error):
                raise
            # Discard the aborted statement's transaction outright: a replay must
            # leave the history and the run state byte-for-byte unchanged.
            connection.rollback()
            LOGGER.info(
                "onboarding phase boundary %s -> %s was already committed for run %s (%s)",
                from_phase,
                to_phase,
                run_id,
                PHASE_REPLAY_NOOP,
            )
            return False

        # onboarding_run_state is a projection of the history above. Only the
        # columns this boundary establishes are written: the account binding, the
        # pause phase, and the counters belong to the phases that own them, and an
        # upsert that reset them would erase durable facts.
        connection.execute(
            """
            INSERT INTO onboarding_run_state (
                run_id, phase, profile_digest, account_ref, updated_at
            ) VALUES (?, ?, ?, '', ?)
            ON CONFLICT(run_id) DO UPDATE SET
                phase = excluded.phase,
                profile_digest = excluded.profile_digest,
                updated_at = excluded.updated_at
            """,
            (run_id, to_phase, profile_digest, now),
        )
        return True

    def commit_phase_with_reservation(
        self,
        *,
        run_id: str,
        from_phase: OnboardingPhase | None,
        to_phase: OnboardingPhase,
        reason_code: OnboardingReasonCode,
        profile_digest: str,
        attempt: int,
        correlation_id: str,
        effect: OnboardingEffect,
        operation_key: str,
        generation: int = 0,
    ) -> ReservedPhaseCommit:
        """Commit one phase boundary and reserve that phase's effect as one unit.

        PRE:  the transition is legal and ``operation_key`` was derived by
              :mod:`ops.onboarding.effects` from durable facts only.
        POST: either the history row, the run-ledger reservation, and the
              onboarding reservation row are all present, or none of them is. A
              replayed boundary writes nothing and reports the standing
              disposition for the key.

        Why one transaction rather than two calls (Requirement 13.13): with a
        separate commit and reservation, a worker that lost its lease between them
        leaves a committed phase whose effect is unreserved, and the worker that
        claims next reserves the key and submits while the first is still in
        flight. Inside one ``BEGIN IMMEDIATE`` there is no such window — the
        second claimant either sees both or neither, and the ledger's
        ``UNIQUE (run_id, operation_key)`` then tells it the effect is taken.

        The phase is committed *before* the reservation within that unit of work,
        which is the ordering Requirement 12.4 asks for: a crash can leave a phase
        with no reservation (safe, the next worker reserves it) but never a
        reservation with no phase (unsafe, the effect would have no owner).
        """

        run = _identifier(run_id, field="run id")
        code = _reason_code(reason_code)
        digest = _profile_digest(profile_digest)
        correlation = _identifier(
            correlation_id, field="correlation id", limit=MAX_CORRELATION_ID_LENGTH
        )
        attempt_number = _attempt(attempt)
        action = _effect(effect)
        key = _identifier(operation_key, field="operation key")
        if generation < 0:
            raise ValueError("effect generation must be zero or greater")
        validate_phase_transition(from_phase, to_phase, code)

        with self._write() as connection:
            committed = self._commit_phase(
                connection,
                run_id=run,
                from_phase=from_phase,
                to_phase=to_phase,
                reason_code=code,
                profile_digest=digest,
                attempt=attempt_number,
                correlation_id=correlation,
            )
            if not committed:
                # ``_commit_phase`` rolled the unit of work back, so the reads
                # below observe only what was already durable.
                return ReservedPhaseCommit(
                    committed=False,
                    plan=self._standing_plan(connection, run_id=run, key=key, action=action),
                )

            intent, created = self._ledger.reserve_side_effect_in_transaction(
                connection, run_id=run, operation_key=key, provider=EFFECT_PROVIDER
            )
            # A fresh insert means no prior attempt existed, which is the only
            # state besides a provable failure that authorizes execution.
            row_status = None if created else _row_status(intent["status"])
            plan = plan_for_row_status(
                operation_key=key,
                action=action,
                row_status=row_status,
                receipt=self._stored_receipt(connection, run_id=run, key=key)
                if row_status == "completed"
                else None,
            )
            if row_status == "failed":
                # Re-open the row so the retry this plan authorizes is itself
                # reserved, mirroring how ops.core.effect_ledger reserves over a
                # failure rather than leaving the key permanently failed.
                self._ledger.update_side_effect_in_transaction(
                    connection, run_id=run, operation_key=key, status="pending"
                )
            self._ledger.record_effect_reservation_in_transaction(
                connection,
                run_id=run,
                operation_key=key,
                effect=action,
                generation=generation,
                phase=to_phase,
                disposition=plan.disposition,
                reason_code=plan.reason_code,
            )
            return ReservedPhaseCommit(committed=True, plan=plan)

    def effect_reservation(
        self, *, run_id: str, operation_key: str
    ) -> EffectReservationRecord | None:
        """The standing reservation for one operation key, or ``None``."""

        run = _identifier(run_id, field="run id")
        key = _identifier(operation_key, field="operation key")
        with self._connect() as connection:
            record = self._ledger.read_effect_reservation_in_transaction(
                connection, run_id=run, operation_key=key
            )
        return None if record is None else _reservation_record(record)

    def reservations(self, *, run_id: str) -> tuple[EffectReservationRecord, ...]:
        """Every standing reservation this run owns, oldest key first.

        The enumeration half of :meth:`effect_reservation`, and read-only like it:
        recovery reads it to learn what a worker arriving now may do about each key,
        and the autonomy outcome reads it to count duplicate skips and ambiguous
        outcomes. Nothing here reserves, completes, or re-opens a key.
        """

        run = _identifier(run_id, field="run id")
        return tuple(
            _reservation_record(record)
            for record in self._ledger.list_effect_reservations(run_id=run)
        )

    def submission_count(self, *, run_id: str, operation_key: str) -> int:
        """How many provider submissions this key has been authorized.

        Derived rather than counted, and the derivation is the guarantee: the row
        is unique per ``(run_id, operation_key)``, so the count is 0 before any
        reservation, 0 after a provable failure, and 1 once a submission has been
        handed out — including while the outcome is unknown. Nothing in this module
        can move it from 1 to 2, which is Requirement 13.10 expressed as an
        arithmetic fact rather than a convention.
        """

        run = _identifier(run_id, field="run id")
        key = _identifier(operation_key, field="operation key")
        with self._connect() as connection:
            intent = self._ledger.read_side_effect_in_transaction(
                connection, run_id=run, operation_key=key
            )
        if intent is None:
            return 0
        return 1 if str(intent["status"]) in SUBMITTED_STATUSES else 0

    def complete_effect_reservation(
        self, *, run_id: str, operation_key: str, receipt: Mapping[str, str]
    ) -> EffectReservationRecord:
        """Record that the reserved effect happened, with its non-secret receipt.

        POST: the standing disposition becomes ``skip`` and carries the receipt, so
              every later arrival adopts the recorded identifiers instead of
              repeating the effect (Requirement 13.6).
        """

        run = _identifier(run_id, field="run id")
        key = _identifier(operation_key, field="operation key")
        with self._write() as connection:
            action = self._reserved_effect(connection, run_id=run, key=key)
            self._ledger.update_side_effect_in_transaction(
                connection, run_id=run, operation_key=key, status="completed"
            )
            plan = plan_for_row_status(
                operation_key=key, action=action, row_status="completed", receipt=receipt
            )
            return _reservation_record(
                self._ledger.record_effect_reservation_in_transaction(
                    connection,
                    run_id=run,
                    operation_key=key,
                    effect=action,
                    generation=self._reserved_generation(connection, run_id=run, key=key),
                    phase=self._reserved_phase(connection, run_id=run, key=key),
                    disposition=plan.disposition,
                    reason_code=plan.reason_code,
                    receipt=receipt,
                )
            )

    def mark_effect_reservation_outcome_unknown(
        self, *, run_id: str, operation_key: str
    ) -> EffectReservationRecord:
        """Mark a reserved effect whose reconciliation stayed ambiguous.

        POST: the submission count for the key is unchanged, and the standing
              disposition becomes ``pause_outcome_unknown`` — a disposition that
              authorizes nothing. No path in this module turns it back into
              ``execute``; only a read-only provider probe that proves the outcome
              can move the key on, through
              :meth:`complete_effect_reservation` (Requirements 13.9, 13.10).
        """

        run = _identifier(run_id, field="run id")
        key = _identifier(operation_key, field="operation key")
        with self._write() as connection:
            action = self._reserved_effect(connection, run_id=run, key=key)
            self._ledger.update_side_effect_in_transaction(
                connection, run_id=run, operation_key=key, status="outcome_unknown"
            )
            return _reservation_record(
                self._ledger.record_effect_reservation_in_transaction(
                    connection,
                    run_id=run,
                    operation_key=key,
                    effect=action,
                    generation=self._reserved_generation(connection, run_id=run, key=key),
                    phase=self._reserved_phase(connection, run_id=run, key=key),
                    disposition="pause_outcome_unknown",
                    reason_code=OUTCOME_UNKNOWN,
                )
            )

    def _standing_plan(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        key: str,
        action: OnboardingEffect,
    ) -> EffectPlan:
        """What the durable ledger already authorizes for one key. Reads only."""

        intent = self._ledger.read_side_effect_in_transaction(
            connection, run_id=run_id, operation_key=key
        )
        row_status = None if intent is None else _row_status(intent["status"])
        return plan_for_row_status(
            operation_key=key,
            action=action,
            row_status=row_status,
            receipt=self._stored_receipt(connection, run_id=run_id, key=key)
            if row_status == "completed"
            else None,
        )

    def _reserved_row(
        self, connection: sqlite3.Connection, *, run_id: str, key: str
    ) -> dict[str, object]:
        record = self._ledger.read_effect_reservation_in_transaction(
            connection, run_id=run_id, operation_key=key
        )
        if record is None:
            raise KeyError("effect reservation was not found")
        return record

    def _reserved_effect(
        self, connection: sqlite3.Connection, *, run_id: str, key: str
    ) -> OnboardingEffect:
        return _effect(str(self._reserved_row(connection, run_id=run_id, key=key)["effect"]))

    def _reserved_generation(self, connection: sqlite3.Connection, *, run_id: str, key: str) -> int:
        return int(str(self._reserved_row(connection, run_id=run_id, key=key)["generation"]))

    def _reserved_phase(
        self, connection: sqlite3.Connection, *, run_id: str, key: str
    ) -> OnboardingPhase:
        return _phase(self._reserved_row(connection, run_id=run_id, key=key)["phase"])

    def _stored_receipt(
        self, connection: sqlite3.Connection, *, run_id: str, key: str
    ) -> dict[str, str] | None:
        record = self._ledger.read_effect_reservation_in_transaction(
            connection, run_id=run_id, operation_key=key
        )
        if record is None:
            return None
        receipt = record["receipt"]
        return None if receipt is None else dict(receipt)

    def current_phase(self, *, run_id: str) -> tuple[OnboardingPhase, int] | None:
        """The last committed phase and attempt, or ``None`` before the first."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT to_phase, attempt
                FROM onboarding_phase_history
                WHERE run_id = ?
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (_identifier(run_id, field="run id"),),
            ).fetchone()
        if row is None:
            return None
        return (_phase(row[0]), int(row[1]))

    def history(self, *, run_id: str) -> tuple[PhaseTransition, ...]:
        """Every committed boundary for the run, ordered by sequence."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sequence, from_phase, to_phase, reason_code, profile_digest,
                       attempt, correlation_id, committed_at
                FROM onboarding_phase_history
                WHERE run_id = ?
                ORDER BY sequence ASC
                """,
                (_identifier(run_id, field="run id"),),
            ).fetchall()
        return tuple(
            PhaseTransition(
                sequence=int(row[0]),
                from_phase=None if row[1] is None else _phase(row[1]),
                to_phase=_phase(row[2]),
                reason_code=_reason_code(str(row[3])),
                profile_digest=str(row[4]),
                attempt=int(row[5]),
                correlation_id=str(row[6]),
                committed_at=str(row[7]),
            )
            for row in rows
        )

    def next_generation(self, *, run_id: str, effect: str) -> int:
        """Advance the effect's generation counter by exactly one and return it."""

        run = _identifier(run_id, field="run id")
        column = _generation_column(effect)
        with self._write() as connection:
            advanced = self._read_generation(connection, run_id=run, column=column) + 1
            connection.execute(
                f"UPDATE onboarding_run_state SET {column} = ?, updated_at = ? WHERE run_id = ?",
                (advanced, _utc_now(), run),
            )
            return advanced

    def current_generation(self, *, run_id: str, effect: str) -> int:
        """The effect's generation counter as it stands, advancing nothing."""

        run = _identifier(run_id, field="run id")
        column = _generation_column(effect)
        with self._connect() as connection:
            return self._read_generation(connection, run_id=run, column=column)

    def next_validation_attempt(self, *, run_id: str) -> int:
        """Advance the run's credential-validation attempt counter by exactly one.

        Same shape as :meth:`next_generation` over a different column, and for the
        same reason: the count has to survive the worker that produced it, because
        a validation retry is a re-entry into ``credential_validation`` rather
        than a loop inside one process.
        """

        run = _identifier(run_id, field="run id")
        with self._write() as connection:
            advanced = self._read_generation(connection, run_id=run, column=VALIDATION_COUNTER) + 1
            connection.execute(
                f"UPDATE onboarding_run_state SET {VALIDATION_COUNTER} = ?, updated_at = ? "
                "WHERE run_id = ?",
                (advanced, _utc_now(), run),
            )
            return advanced

    def next_verification_attempt(self, *, run_id: str) -> int:
        """Advance the run's email-verification attempt counter by exactly one.

        The mailbox read is the one phase step that routinely ends in a deferral,
        so this counter is what turns "poll again later" into a ladder with a last
        rung (Requirements 7.19, 7.28) instead of an unbounded wait.
        """

        run = _identifier(run_id, field="run id")
        with self._write() as connection:
            advanced = (
                self._read_generation(connection, run_id=run, column=VERIFICATION_COUNTER) + 1
            )
            connection.execute(
                f"UPDATE onboarding_run_state SET {VERIFICATION_COUNTER} = ?, updated_at = ? "
                "WHERE run_id = ?",
                (advanced, _utc_now(), run),
            )
            return advanced

    def verification_attempts(self, *, run_id: str) -> int:
        """The run's consumed verification attempts, without advancing the ladder."""

        return self._counter(run_id=run_id, column=VERIFICATION_COUNTER)

    def validation_attempts(self, *, run_id: str) -> int:
        """The run's consumed validation attempts, without advancing the ladder."""

        return self._counter(run_id=run_id, column=VALIDATION_COUNTER)

    def _counter(self, *, run_id: str, column: str) -> int:
        """One durable counter as it stands. Zero for a run with no state row.

        A missing projection row means the run has committed no boundary, so it has
        consumed no attempt of anything: zero is the fact rather than an absence to
        raise about, because this read serves the autonomy outcome of a run that may
        have blocked before its first phase.
        """

        run = _identifier(run_id, field="run id")
        with self._connect() as connection:
            try:
                return self._read_generation(connection, run_id=run, column=column)
            except KeyError:
                return 0

    def record_captcha_pause(self, *, run_id: str, phase_at_pause: OnboardingPhase) -> CaptchaPause:
        """Durably record the phase at pause and count this CAPTCHA prompt.

        Both writes are one statement on purpose: a recorded phase with an
        uncounted prompt would let a run pause without ever reaching its budget,
        and a counted prompt with no recorded phase would leave a resume nowhere
        to re-enter (Requirements 11.2, 11.3).

        POST: increments by exactly one per call, so the count is the number of
              pauses the run has actually taken rather than the number of times a
              worker looked at it.
        """

        run = _identifier(run_id, field="run id")
        phase = _phase(phase_at_pause)
        with self._write() as connection:
            prompts = (
                self._read_generation(connection, run_id=run, column=CAPTCHA_PROMPT_COUNTER) + 1
            )
            connection.execute(
                f"UPDATE onboarding_run_state SET phase_at_pause = ?, "
                f"{CAPTCHA_PROMPT_COUNTER} = ?, updated_at = ? WHERE run_id = ?",
                (phase, prompts, _utc_now(), run),
            )
            return CaptchaPause(phase_at_pause=phase, prompts=prompts)

    def captcha_pause(self, *, run_id: str) -> CaptchaPause:
        """The run's recorded phase at pause and its CAPTCHA prompt count."""

        run = _identifier(run_id, field="run id")
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT phase_at_pause, {CAPTCHA_PROMPT_COUNTER} "
                "FROM onboarding_run_state WHERE run_id = ?",
                (run,),
            ).fetchone()
        if row is None:
            # Same absence the generation counters report: the projection row is
            # written by the first committed boundary, so a missing row means the
            # run has no phase history at all.
            raise KeyError("onboarding run state was not found")
        return CaptchaPause(
            phase_at_pause=None if row[0] is None else _phase(row[0]),
            prompts=int(row[1]),
        )

    def record_admission_prompt(self, *, run_id: str) -> int:
        """Count the run's one admission prompt, and only while it is due.

        The whole of Requirement 11.13 is this statement's ``WHERE`` clause. The
        row is updated only when the run's committed phase *is*
        ``awaiting_admission`` and the counter is still zero, so a second call, a
        second worker, and a call made from any other phase all match nothing.

        POST: returns how many prompts this call authorizes — 1 exactly once per
              run, 0 every other time — so the caller emits a prompt iff the
              durable count moved. Nothing is written on the 0 path.
        """

        run = _identifier(run_id, field="run id")
        with self._write() as connection:
            cursor = connection.execute(
                f"UPDATE onboarding_run_state SET {ADMISSION_PROMPT_COUNTER} = ?, "
                f"updated_at = ? WHERE run_id = ? AND phase = ? "
                f"AND {ADMISSION_PROMPT_COUNTER} = 0",
                (ADMISSION_PROMPT_LIMIT, _utc_now(), run, ADMISSION_PROMPT_PHASE),
            )
            return ADMISSION_PROMPT_LIMIT if cursor.rowcount == 1 else 0

    def admission_prompts(self, *, run_id: str) -> int:
        """How many admission prompts the run has emitted: 0 or 1."""

        run = _identifier(run_id, field="run id")
        with self._connect() as connection:
            return self._read_generation(connection, run_id=run, column=ADMISSION_PROMPT_COUNTER)

    @staticmethod
    def _read_generation(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        column: str,
    ) -> int:
        # The column name is one of this module's own counter constants, never a
        # caller's string, so the interpolation carries no untrusted input.
        row = connection.execute(
            f"SELECT {column} FROM onboarding_run_state WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            # A generation belongs to a run that has committed a phase. Creating
            # the row here would have to invent a profile digest and an account
            # binding, so the absence is reported instead.
            raise KeyError("onboarding run state was not found")
        return int(row[0])

    @staticmethod
    def _next_sequence(connection: sqlite3.Connection, run_id: str) -> int:
        """The next 1-based sequence number for the run.

        Read inside the write transaction, so the ``UNIQUE (run_id, sequence)``
        constraint cannot be raced into a gap by a concurrent committer.
        """

        row = connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM onboarding_phase_history WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return int(row[0]) + 1

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
            # Foreign keys are enforced here as they are for every other ops.db
            # writer: a phase boundary for a run that does not exist is a bug, not
            # a row to keep.
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA secure_delete = ON")
            yield connection
        finally:
            connection.close()


@dataclass(frozen=True, slots=True)
class RenewalCheck:
    """The guard's answer at the top of one driver iteration.

    ``lease`` is present only for ``status == "ok"``: on either stop status there
    is no lease this worker may act under, and returning ``None`` makes that a
    type-level fact rather than a convention the driver has to remember.
    """

    status: LeaseGuardStatus
    lease: Lease | None

    @property
    def may_drive(self) -> bool:
        """Whether the driver may run the next step at all."""

        return self.status == "ok"


class LeaseGuard:
    """Keeps one run's lease alive, and stops the driver the moment it cannot.

    The guard owns three decisions the driver would otherwise scatter across its
    loop, and each one is a Requirement:

    *Renew on cadence, not on every pass* (Requirement 16.5). :meth:`before_step`
    renews only once the renewal interval has elapsed since the last confirmed
    renewal, so a fast loop does not hammer the store and a slow one still renews
    before its deadline. The interval comes from :class:`LeaseTimings`, which
    enforces the at-most-one-third relation the other two decisions rest on.

    *A lost fencing token stops everything, immediately* (Requirement 16.6). A
    renewal returning ``None`` proves another worker claimed the run. The guard
    latches ``fenced`` — no later call re-attempts the renewal or hands back a
    lease — and it does not touch the stored lease, which now belongs to the
    successor.

    *An unconfirmed renewal is not a lost one* (Requirement 16.7). A renewal that
    *raises* is a transient store error, and while the deadline is still in the
    future this worker demonstrably still owns the run. The first such failure is
    logged and driving continues; the second exits. An expiry reached with a
    failing store also exits, because past the deadline the run is claimable and
    the guard can no longer show the lease is live.

    Release is the fourth decision, and it is structural: the guard is a context
    manager, so ``with LeaseGuard(...) as guard:`` releases on every exit path,
    exactly once, whether the body returned, raised, or was fenced out
    (Requirement 16.13). A repeat :meth:`release` is a local no-op that never
    reaches the store, so "exactly once" does not depend on the store's own
    idempotence.

    The clock is injectable for the same reason the lease store's is: expiry is a
    comparison against stored text, so a test moves the clock instead of sleeping
    through a real TTL.
    """

    def __init__(
        self,
        *,
        store: LeaseStore,
        lease: Lease,
        timings: LeaseTimings = DEFAULT_LEASE_TIMINGS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._lease = lease
        self._timings = timings
        self._clock = clock or _utc_moment
        # The claim that produced this lease is itself a confirmation, so the
        # first renewal is due one interval after it rather than immediately.
        self._confirmed_at = self._moment()
        self._failures = 0
        self._status: LeaseGuardStatus = "ok"
        self._released = False

    @property
    def lease(self) -> Lease:
        """The most recently confirmed lease, deadline included.

        Kept readable after a stop so an unwinding caller can still release it and
        log which token it held; :attr:`status` is what says whether it may act.
        """

        return self._lease

    @property
    def status(self) -> LeaseGuardStatus:
        """The guard's standing verdict. Latches on the first stop."""

        return self._status

    @property
    def released(self) -> bool:
        """Whether the release has already happened."""

        return self._released

    def before_step(self) -> RenewalCheck:
        """Confirm ownership before the driver takes its next step.

        POST: ``status == "ok"`` only when a live lease with a future deadline is
              held — either freshly renewed, or confirmed within the last renewal
              interval. On any other status the driver performs no further side
              effect and unwinds; the stop is latched, so calling again cannot
              revive it.
        """

        if self._status != "ok":
            return RenewalCheck(status=self._status, lease=None)

        now = self._moment()
        if not self._renewal_due(now):
            return RenewalCheck(status="ok", lease=self._lease)

        try:
            renewed = self._store.renew(lease=self._lease, ttl_seconds=self._timings.ttl_seconds)
        except Exception:
            # Any failure to *reach* the store leaves ownership unconfirmed rather
            # than lost, which is a different question from being fenced out and
            # is answered by the deadline and the failure count below.
            return self._unconfirmed(now)

        if renewed is None:
            # Fenced out. The stored lease belongs to another worker now, so the
            # guard writes nothing and reports the stop.
            self._status = "fenced"
            LOGGER.warning(
                "onboarding worker %s lost the fencing token for run %s at token %d; stopping",
                self._lease.worker_id,
                self._lease.run_id,
                self._lease.fencing_token,
            )
            return RenewalCheck(status="fenced", lease=None)

        self._lease = renewed
        self._confirmed_at = now
        self._failures = 0
        return RenewalCheck(status="ok", lease=renewed)

    def release(self) -> bool:
        """Release the lease, at most once for the life of this guard.

        POST: the store is asked to release exactly once; every later call returns
              ``False`` without touching it. ``True`` means this lease still owned
              the run and it is now free. ``False`` from the first call is the
              reported no-op of Requirement 16.12 — the lease was superseded, and
              the successor's lease is left exactly as it was.

        Safe on every exit path, including after a fence: the store's release
        carries the same fencing predicate as its renewal, so a fenced-out
        worker's release matches no row and changes nothing.
        """

        if self._released:
            return False
        # Latched before the call, so a store that raises cannot lead to a second
        # release attempt during a nested unwind.
        self._released = True
        released = self._store.release(lease=self._lease)
        if not released:
            LOGGER.info(
                "onboarding lease release for run %s was a no-op; the lease was superseded",
                self._lease.run_id,
            )
        return released

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        # The release lives here rather than in the driver's body so that
        # "exactly once on every exit path" holds for paths nobody wrote down.
        self.release()

    def _unconfirmed(self, now: datetime) -> RenewalCheck:
        """Account for one renewal that could not be confirmed."""

        self._failures += 1
        expired = self._lease.is_expired(now=now)
        if expired or self._failures >= MAX_RENEWAL_FAILURES:
            self._status = "renewal_unconfirmed"
            LOGGER.warning(
                "onboarding lease renewal for run %s failed %d time(s)%s; finishing without effects",
                self._lease.run_id,
                self._failures,
                " past the deadline" if expired else " with a future deadline",
                exc_info=True,
            )
            return RenewalCheck(status="renewal_unconfirmed", lease=None)
        # One failure with a future deadline: the one-third cadence means the
        # lease is still demonstrably live, so driving continues and the next call
        # retries the renewal.
        LOGGER.info(
            "onboarding lease renewal for run %s failed once with a future deadline; retrying",
            self._lease.run_id,
            exc_info=True,
        )
        return RenewalCheck(status="ok", lease=self._lease)

    def _renewal_due(self, now: datetime) -> bool:
        """Whether the renewal interval has elapsed since the last confirmation.

        An expired deadline always makes a renewal due, because expiry is longer
        than the interval — which is why an expiry is answered by attempting the
        renewal that can settle ownership rather than by a guess.
        """

        elapsed = (now - self._confirmed_at).total_seconds()
        return elapsed >= self._timings.renew_interval_seconds

    def _moment(self) -> datetime:
        moment = self._clock()
        if moment.tzinfo is None:
            raise ValueError("the lease clock must return an aware datetime")
        return moment.astimezone(UTC)


def _utc_moment() -> datetime:
    return datetime.now(UTC)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _identifier(value: str, *, field: str, limit: int = MAX_IDENTIFIER_LENGTH) -> str:
    """Accept a bounded, single-line identifier and reject anything else."""

    if not value or len(value) > limit:
        raise ValueError(f"{field} is invalid")
    if any(character.isspace() or not character.isprintable() for character in value):
        raise ValueError(f"{field} is invalid")
    return value


def _profile_digest(value: str) -> str:
    if len(value) != PROFILE_DIGEST_LENGTH:
        raise ValueError("profile digest must be a sha256 hex digest")
    return value


def _attempt(value: int) -> int:
    if value < 0:
        raise ValueError("attempt must be zero or greater")
    return value


def _reason_code(value: str) -> OnboardingReasonCode:
    """Keep the reason column inside the closed vocabulary.

    The type annotation says as much, but this column is the one an operator reads
    back, so the closed list is also enforced at the write boundary: no provider
    or page text can arrive here as a reason code.
    """

    if value not in ONBOARDING_REASON_CODES:
        raise ValueError("reason code is not an onboarding reason code")
    return value


def _phase(value: object) -> OnboardingPhase:
    if not isinstance(value, str) or value not in ONBOARDING_PHASES:
        raise RuntimeError("phase history row carries an unknown phase")
    return value


def _effect(value: str) -> OnboardingEffect:
    """Keep the reserved effect inside the three provider-visible effects."""

    if value not in ONBOARDING_EFFECTS:
        raise ValueError("effect is not an onboarding effect")
    return value


def _row_status(value: object) -> EffectRowStatus:
    """Read a run-ledger reservation status as the ledger's row vocabulary."""

    for status in EFFECT_ROW_STATUSES:
        if value == status:
            return status
    raise RuntimeError("side-effect reservation row carries an unknown status")


def _disposition(value: object) -> EffectDisposition:
    """Read a stored disposition back into the closed vocabulary."""

    for disposition in ONBOARDING_EFFECT_DISPOSITIONS:
        if value == disposition:
            return disposition
    raise RuntimeError("effect reservation row carries an unknown disposition")


def _reservation_record(record: Mapping[str, Any]) -> EffectReservationRecord:
    """Read one durable reservation row into its closed-vocabulary form."""

    receipt = record["receipt"]
    return EffectReservationRecord(
        run_id=str(record["run_id"]),
        operation_key=str(record["operation_key"]),
        effect=_effect(str(record["effect"])),
        generation=int(record["generation"]),
        phase=_phase(record["phase"]),
        disposition=_disposition(record["disposition"]),
        receipt=None if receipt is None else {str(k): str(v) for k, v in receipt.items()},
        reason_code=_reason_code(str(record["reason_code"])),
    )


def _generation_column(effect: str) -> str:
    column = GENERATION_COUNTERS.get(effect)
    if column is None:
        raise ValueError("effect has no generation counter")
    return column


def _is_unique_violation(error: sqlite3.IntegrityError) -> bool:
    """Whether SQLite refused the write for uniqueness and nothing else."""

    return error.sqlite_errorcode in _UNIQUE_VIOLATION_CODES


# --- the phase driver -------------------------------------------------------

# The per-run answer to "did this need a human, and where?" (design LL-1.7).
AutonomyVerdict = Literal["fully_autonomous", "operator_assisted", "blocked", "cancelled"]
AUTONOMY_VERDICTS: Final[tuple[AutonomyVerdict, ...]] = get_args(AutonomyVerdict)

# Import-time proof that the verdict this module computes is one the durable record
# admits. ``ops.core.storage`` types the vocabulary out rather than importing it from
# here, because this module imports the run ledger and the reverse import would be
# a cycle; this assertion is what keeps the two from drifting, so a verdict added
# on one side fails to import instead of failing a CHECK against a live run.
assert AUTONOMY_VERDICTS == AUTONOMY_VERDICT_VALUES, (
    "the autonomy verdict vocabulary and the outcome table's CHECK must agree"
)

# The phase a browser-bearing phase advances into once the loop reports `done`.
# Declared as data rather than decided per handler so the walk through the
# machine is readable in one place: Requirement 9.1 is the ``authenticated ->
# developer_app`` row, and 9.11 is the ``developer_app -> credential_generation``
# one. The key set is exactly the loop-driven phases, which is asserted below.
PHASE_SUCCESSORS: Final[dict[OnboardingPhase, OnboardingPhase]] = {
    "route_selected_login": "authenticated",
    "signup": "email_verification",
    "email_verification": "authenticated",
    "authenticated": "developer_app",
    "developer_app": "credential_generation",
    "credential_generation": "vault_storage",
}

# Import-time proof that the walk above is a walk the phase machine admits, so a
# successor row that the legal table refuses is a failure to import rather than a
# refused transition discovered mid-run against a live provider.
assert all(
    is_legal_phase_transition(source, target) for source, target in PHASE_SUCCESSORS.items()
), "every declared phase successor must be a legal transition"

# Phases the driver stops at rather than drives: a human or a timer owns the run
# from here, and re-entry is the resume path (tasks 18 and 20), not this loop.
WAITING_PHASES: Final[frozenset[OnboardingPhase]] = frozenset({"paused", "captcha_paused"})

# Phase -> the provider-visible effect whose operation key that phase reserves.
# Declared here because it is what makes Requirement 12.4 checkable rather than
# merely intended: before the driver enters one of these phases, the boundary
# into it must already be durable, so the reservation can never be the first
# durable fact about the phase that owns it.
EFFECT_BEARING_PHASES: Final[dict[OnboardingPhase, OnboardingEffect]] = {
    "signup": "signup_submit",
    "developer_app": "create_dev_app",
    "credential_generation": "generate_credential",
}

# The reason code an outcome carries when the driver claimed the run and stopped
# before any phase step produced one — a fence on the first iteration, or a run
# already parked at a waiting phase.
NO_STEP_TAKEN: Final[OnboardingReasonCode] = "lease_claimed"

# The autonomous duplicate-account recovery (design LL-1.1, Requirements 6.7,
# 6.8). The provider answered the signup submission with "this account already
# exists", and the account it means is the one this run created credentials for
# and stored *before* submitting — so the run re-routes to login under its own
# stored references and no human is asked anything.
DUPLICATE_ACCOUNT_REROUTE: Final[OnboardingReasonCode] = "signup_rejected_duplicate_account"
DUPLICATE_ACCOUNT_REROUTE_SOURCE: Final[OnboardingPhase] = "signup"
DUPLICATE_ACCOUNT_REROUTE_TARGET: Final[OnboardingPhase] = "route_selected_login"

# Import-time proof that the recovery the driver performs is one the phase machine
# admits, for the same reason PHASE_SUCCESSORS is checked below: a table this
# module reads must not disagree with the table that refuses transitions.
assert is_legal_phase_transition(
    DUPLICATE_ACCOUNT_REROUTE_SOURCE, DUPLICATE_ACCOUNT_REROUTE_TARGET
), "the duplicate-account re-route must be a legal phase transition"

# What a handler or the loop asks the driver to do about the phase it just drove.
#   ``advance`` -> commit a boundary into ``next_phase``
#   ``yield``   -> commit nothing, re-queue the run at ``not_before``
#   ``pause``   -> commit a boundary into ``paused`` carrying the reason code
PhaseStepKind = Literal["advance", "yield", "pause"]


class PhaseNotDrivable(RuntimeError):
    """The driver reached a phase with neither a registered handler nor a goal.

    A wiring error rather than a run outcome, so it is raised: silently pausing
    would record a provider-shaped reason code for a defect on this side. The
    lease is still released, because the guard releases on every exit path.
    """

    def __init__(self, phase: OnboardingPhase, detail: str) -> None:
        super().__init__(f"phase {phase!r} is not drivable: {detail}")
        self.phase = phase


@dataclass(frozen=True, slots=True)
class PhaseStep:
    """One phase's request for a transition. Carries no authority to write it.

    This is the whole hand-off from a handler (or from the action loop's mapped
    outcome) back to the driver, and it is deliberately inert: a step names a
    target phase and a reason code, and only :func:`drive_run` turns that into a
    durable boundary (Requirements 12.9, 4.20).

    ``profile_digest`` is present only for the step that first establishes it —
    the research phase, which builds the profile the rest of the run is
    attributable to. Every later step leaves it ``None`` and the driver supplies
    the run's own digest, which is what makes "one profile per run" hold without
    each handler restating it.
    """

    kind: PhaseStepKind
    reason_code: OnboardingReasonCode
    next_phase: OnboardingPhase | None = None
    not_before: str | None = None
    profile_digest: str | None = None

    def __post_init__(self) -> None:
        if self.reason_code not in ONBOARDING_REASON_CODES:
            raise ValueError("a phase step carries an onboarding reason code")
        if self.kind == "advance":
            if self.next_phase is None:
                raise ValueError("an advancing step names the phase it advances into")
            if self.not_before is not None:
                raise ValueError("an advancing step does not carry a deferral time")
        elif self.kind == "yield":
            if self.not_before is None:
                raise ValueError("a yielding step names the time it becomes ready again")
            if self.next_phase is not None:
                raise ValueError("a yielding step commits no transition")
        elif self.next_phase is not None or self.not_before is not None:
            # A pause always targets ``paused``; naming it twice would let a
            # handler pause "into" some other phase.
            raise ValueError("a pausing step names neither a target phase nor a deferral time")

    @classmethod
    def advance(
        cls,
        next_phase: OnboardingPhase,
        reason_code: OnboardingReasonCode,
        *,
        profile_digest: str | None = None,
    ) -> PhaseStep:
        """Ask for a boundary into ``next_phase``."""

        return cls(
            kind="advance",
            reason_code=reason_code,
            next_phase=next_phase,
            profile_digest=profile_digest,
        )

    @classmethod
    def defer(cls, not_before: str, reason_code: OnboardingReasonCode) -> PhaseStep:
        """Ask to be re-queued at ``not_before``, with the phase left where it is."""

        return cls(kind="yield", reason_code=reason_code, not_before=not_before)

    @classmethod
    def pause(cls, reason_code: OnboardingReasonCode) -> PhaseStep:
        """Ask for a boundary into ``paused`` carrying ``reason_code``."""

        return cls(kind="pause", reason_code=reason_code)


@dataclass(frozen=True, slots=True)
class AutonomyOutcome:
    """The per-run answer to "did this need a human, and where?" (LL-1.7).

    The durable record behind the autonomy metrics, and never a projection of
    logs: every field is a count the driver held while it drove, or a fact about
    the phase it stopped at. ``other_operator_prompts`` is pinned to zero at
    construction because Requirement 11.15 is a claim about the system rather
    than a number to report — CAPTCHA and the pre-execution admission decision
    are the only prompts that may exist, so any third one is a defect and is
    refused here rather than recorded.

    ``drive_run`` returns it and, at a terminal phase, writes it exactly once
    through :class:`AutonomyOutcomeStore` (Requirement 20.4).
    """

    run_id: str
    profile_digest: str
    verdict: AutonomyVerdict
    terminal_phase: OnboardingPhase
    reason_code: OnboardingReasonCode
    started_at: str
    ended_at: str
    duration_seconds: int = 0
    admission_prompts: int = 0  # 0 on the login route, else 1
    captcha_prompts: int = 0
    other_operator_prompts: int = 0  # MUST be 0 (Requirement 11.15)
    model_calls: int = 0
    actions_executed: int = 0
    navigation_denials: int = 0
    phases_replayed: int = 0
    effects_skipped_as_duplicate: int = 0
    outcome_unknown_effects: int = 0
    verification_attempts: int = 0
    validation_attempts: int = 0

    def __post_init__(self) -> None:
        _identifier(self.run_id, field="run id")
        # Empty is admitted for a run that never got as far as building a
        # profile; anything else must be a real content address.
        if self.profile_digest:
            _profile_digest(self.profile_digest)
        if self.verdict not in AUTONOMY_VERDICTS:
            raise ValueError("verdict is not an autonomy verdict")
        _reason_code(self.reason_code)
        _phase(self.terminal_phase)
        if self.other_operator_prompts != 0:
            raise ValueError(
                "an onboarding run emits no operator prompt beyond admission and captcha"
            )
        if self.admission_prompts not in (0, 1):
            raise ValueError("the admission prompt is emitted at most once per run")
        if (
            min(
                self.duration_seconds,
                self.captcha_prompts,
                self.model_calls,
                self.actions_executed,
                self.navigation_denials,
                self.phases_replayed,
                self.effects_skipped_as_duplicate,
                self.outcome_unknown_effects,
                self.verification_attempts,
                self.validation_attempts,
            )
            < 0
        ):
            raise ValueError("autonomy outcome counters cannot be negative")

    def is_fully_autonomous(self) -> bool:
        """True when only the pre-execution admission decision involved a human."""

        return self.captcha_prompts == 0 and self.other_operator_prompts == 0

    def as_record(self) -> dict[str, object]:
        """The 19 fields, keyed by name, for the durable outcome row (20.5).

        ``asdict`` rather than a hand-written mapping so the record cannot carry
        fewer fields than the dataclass declares: the store requires exactly the
        19 declared column names, so a field added here without a column, or a
        column renamed without the field, is a refusal at the write boundary
        rather than a quietly missing count.
        """

        return asdict(self)


# The outcome's fields split by shape, derived from the dataclass rather than
# typed out, so the reader below cannot miss a counter that was added above.
_AUTONOMY_TEXT_FIELDS: Final[tuple[str, ...]] = (
    "run_id",
    "profile_digest",
    "verdict",
    "terminal_phase",
    "reason_code",
    "started_at",
    "ended_at",
)
_AUTONOMY_COUNT_FIELDS: Final[tuple[str, ...]] = tuple(
    declared.name
    for declared in fields(AutonomyOutcome)
    if declared.name not in _AUTONOMY_TEXT_FIELDS
)


class AutonomyOutcomeStore(Protocol):
    """Where a run's one autonomy outcome becomes durable (Requirement 20.4).

    One verb, and it takes the whole :class:`AutonomyOutcome` rather than fields,
    so nothing that is not part of the outcome can be written through this port.
    Write-once is the store's guarantee rather than the driver's: the answer says
    whether *this* call wrote the record, which is what lets a terminal phase be
    re-driven after a crash without producing a second one.
    """

    def record_autonomy_outcome(self, *, outcome: AutonomyOutcome) -> bool:
        """Write the run's outcome. ``False`` means it already had one.

        POST: after the first call the run has exactly one outcome record, and no
              later call replaces it.
        """


class AutonomyOutcomeReader(Protocol):
    """Where a reader — the API's run detail projection — finds one run's outcome.

    Separate from :class:`AutonomyOutcomeStore` so the projection depends on a port
    with no write verb on it: a response handler cannot record an outcome, and a
    driver holding the store cannot be handed a reader by mistake.

    A record exists only for a run that reached a terminal phase, because that is
    the only place :func:`drive_run` writes one. So ``None`` means "not terminal
    yet", which is exactly the condition Requirement 20.8 projects on.
    """

    def read_autonomy_outcome(self, *, run_id: str) -> AutonomyOutcome | None:
        """The run's recorded outcome, or ``None`` if it has none yet."""


class LedgerAutonomyOutcomes:
    """The autonomy outcome, recorded in the run ledger's own table.

    The adapter is thin on purpose: ``ops.core.storage`` owns the DDL whose PRIMARY KEY
    and CHECKs are the actual guarantees — one record per run, no third operator
    prompt, and no ``fully_autonomous`` verdict beside a non-zero prompt count —
    so there is nothing for this class to re-decide.
    """

    def __init__(self, ledger: OperationsStorage) -> None:
        self._ledger = ledger

    def record_autonomy_outcome(self, *, outcome: AutonomyOutcome) -> bool:
        """Write one run's outcome; ``False`` means the run already had one."""

        return self._ledger.record_autonomy_outcome(outcome=outcome.as_record())

    def read_autonomy_outcome(self, *, run_id: str) -> AutonomyOutcome | None:
        """The run's recorded outcome, or ``None`` if it has not reached one.

        Rebuilt as an :class:`AutonomyOutcome` rather than handed back as a row —
        the same choice :meth:`~ops.core.storage.OperationsStorage.read_admission_decision`
        makes — so a stored record passes the construction checks a fresh one does
        before the API projects it. A row whose verdict, phase, or reason code is
        not a word this module knows is a corrupted record, and it raises instead of
        being rendered.
        """

        record = self._ledger.read_autonomy_outcome(_identifier(run_id, field="run id"))
        if record is None:
            return None
        verdict = record["verdict"]
        if verdict not in AUTONOMY_VERDICTS:
            raise RuntimeError("stored autonomy verdict is not a known verdict")
        counts = {name: int(record[name]) for name in _AUTONOMY_COUNT_FIELDS}
        return AutonomyOutcome(
            run_id=str(record["run_id"]),
            profile_digest=str(record["profile_digest"]),
            verdict=cast(AutonomyVerdict, verdict),
            terminal_phase=_phase(record["terminal_phase"]),
            reason_code=_reason_code(str(record["reason_code"])),
            started_at=str(record["started_at"]),
            ended_at=str(record["ended_at"]),
            **counts,
        )


class PhaseGoalFactory(Protocol):
    """Where the driver gets the goal it drives a browser-bearing phase toward.

    A port rather than a table because a goal's prose and its reviewed URLs come
    from the run's profile, and the profile is built at runtime.
    """

    def goal_for(self, *, phase: OnboardingPhase, profile: ProviderProfile) -> PhaseGoal:
        """The goal for ``phase``, built from the run's committed profile.

        POST: ``goal.phase == phase`` and its postconditions are the declared
              ones for that phase, so no goal can lower the bar for `done`.
        """


class LoopSessionFactory(Protocol):
    """How the driver obtains the browser session one phase is driven through.

    Takes the lease so an implementation can bind or reattach the session under
    the same ownership proof the driver is acting under.
    """

    async def session_for(
        self, *, run_id: str, phase: OnboardingPhase, lease: Lease
    ) -> LoopSession:
        """An active session bound to this run for the duration of ``phase``."""


class PhaseHandler(Protocol):
    """One phase's own driver, for the phases no browser loop can drive.

    Research, the vault probe, admission, vault storage, and credential
    validation are decisions and I/O rather than page walks. Each returns a
    :class:`PhaseStep` and commits nothing.
    """

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Drive ``phase`` once and report what should happen to it."""


class LoginReferenceBinder(Protocol):
    """Where the login route gets its credential references after a duplicate.

    The signup phase stored one vault reference per login field *before* it
    submitted the form (Requirement 6.2), so when the provider answers "that
    account already exists" the references the run needs in order to sign in are
    already durable. This port is what adopts them as the run's *login*
    references (Requirement 6.8), and its shape is the guarantee that doing so
    needs no human: there is no prompt verb here to call, and no method that
    could return a credential value — references only.
    """

    def adopt_signup_references_for_login(
        self, *, run_id: str, profile_digest: str
    ) -> tuple[tuple[str, str], ...]:
        """Bind the run's stored signup references as its login references.

        POST: returns ``(login field, vault://app/kind/id)`` pairs for every login
              field the run can sign in with, and is idempotent — a second call
              for the same run rebinds the same references rather than minting or
              storing anything new, which is what lets the driver call it on both
              the first pass and on a resume after a crash.
        """


class RunPlanner(Protocol):
    """Produce a pre-flight plan for one reviewed recipe."""

    def plan_for(self, *, recipe: AppRecipe, revision: int) -> PlanOutcome | PlanRefusal:
        """Return a plan outcome or a typed refusal."""


class RunPlanValidator(Protocol):
    """Validate a plan against its reviewed recipe."""

    def __call__(self, plan: RunPlan, *, recipe: AppRecipe) -> PlanRefusal | None: ...


@dataclass(frozen=True, slots=True)
class OnboardingDeps:
    """Everything :func:`drive_run` needs, injected at the composition root.

    Every field is a port from design LL-2, so the driver has no knowledge of
    SQLite, of an inference backend, or of a browser. The three defaults are the
    ones a deployment rarely overrides: the loop budget, the lease timings, and
    the clock — and the clock is injectable for the same reason the guard's is,
    so a test moves time instead of sleeping through a TTL.
    """

    leases: LeaseStore
    phases: PhaseHistoryStore
    profiles: ProviderProfileStore
    queue: RunQueue
    goals: PhaseGoalFactory
    sessions: LoopSessionFactory
    decider: CandidateDecider
    telemetry: LoopTelemetry
    # Where the login route's references come from after the provider rejected
    # signup as a duplicate. Optional because only that one recovery reads it: a
    # deployment that never re-routes never needs it wired, and a re-route with no
    # binder wired is refused rather than escalated to a human.
    logins: LoginReferenceBinder | None = None
    # The mailbox the email-verification phase is resolved through. Optional for
    # the same reason ``logins`` is: a deployment that never signs a run up never
    # needs it, and an absent mailbox is a pause with ``verification_unresolved``
    # and zero consumed messages (Requirement 7.3) rather than a failure. Declared
    # as the port, so nothing here knows which mail vendor is behind it.
    verification: VerificationProvider | None = None
    # Phase -> its own driver, for the phases the action loop cannot drive. A
    # handler registered for a loop-driven phase wins, which is how a phase with
    # provider-specific ordering (signup's store-before-submit, task 15.1) takes
    # over from the generic loop dispatch.
    handlers: Mapping[OnboardingPhase, PhaseHandler] = field(default_factory=dict)
    # Where a terminal run's autonomy outcome is written (Requirement 20.4).
    # Optional so a caller that only wants the returned outcome — a test, or a
    # deployment measuring nothing — needs nothing wired; an unwired store is
    # logged rather than raised, because a recorded run that has already reached a
    # terminal phase must not be undone by a missing metrics sink.
    outcomes: AutonomyOutcomeStore | None = None
    # Where a CAPTCHA pause becomes durable. Optional, and an absent store is why
    # the driver still has the inert transition from
    # :func:`step_for_loop_result`: without a pause store there is nowhere to
    # record the phase at pause, and committing a pause with nowhere to resume to
    # would be worse than pausing without the durable prompt count.
    pauses: CaptchaPauseStore | None = None
    # The mailbox-side facts and the still-alive session the verification phase is
    # driven with. Optional for the same reason ``verification`` is: a deployment
    # that never signs a run up never reaches the phase, and an unwired binding
    # leaves ``email_verification`` to the generic loop dispatch.
    verification_binding: VerificationBinding | None = None
    # Where a one-time verification code is staged so it resolves inside the
    # browser process rather than here (Requirement 7.32).
    vault: VerificationSecretVault | None = None
    # Where the run's plan is recorded and read back, and where it comes from.
    # Both optional, and either one missing leaves planning inert: no plan row is
    # written, adherence has nothing to compare against, and the run is driven
    # exactly as a deployment without a planner drives it.
    plans: RunPlanStore | None = None
    planner: RunPlanner | None = None
    plan_validator: RunPlanValidator = validate_plan
    # The run's standing effect reservations, read-only. Feeds the duplicate-skip
    # and ambiguous-outcome counters on the autonomy outcome; nothing on this port
    # can reserve or complete an effect.
    effects: RecoveryEffectReader | None = None
    budget: LoopBudget = field(default_factory=LoopBudget)
    # The per-step bound on one browser operation, so a hung step cannot freeze a
    # phase (reliability R4.7).
    deadlines: StepDeadlines = field(default_factory=StepDeadlines)
    # ``None`` means the module default, resolved where it is used rather than
    # here: both budget types are declared further down the module, next to the
    # ladders they bound.
    captcha_budget: CaptchaBudget | None = None
    verification_budget: VerificationBudget | None = None
    timings: LeaseTimings = DEFAULT_LEASE_TIMINGS
    clock: Callable[[], datetime] = _utc_moment


@dataclass(slots=True)
class _RunTally:
    """The counters the driver holds while it drives, for the autonomy outcome.

    Two shapes live here. ``model_calls`` through ``admission_prompts`` are what
    this walk did, which only this process can know. The four below them are
    durable per-RUN totals read back from the counters and reservation dispositions
    the run already carries — a walk-local count would restart at zero after a
    crash and under-report every metric computed from them (Requirement 20.5).
    """

    model_calls: int = 0
    actions_executed: int = 0
    navigation_denials: int = 0
    phases_replayed: int = 0
    captcha_prompts: int = 0
    admission_prompts: int = 0
    verification_attempts: int = 0
    validation_attempts: int = 0
    effects_skipped_as_duplicate: int = 0
    outcome_unknown_effects: int = 0

    def record(self, result: LoopResult) -> None:
        self.model_calls += result.model_calls
        self.actions_executed += result.actions_executed
        self.navigation_denials += result.navigation_denials

    def adopt_durable_counters(self, *, run_id: str, deps: OnboardingDeps) -> None:
        """Read the four per-run totals no worker can hold in memory.

        Every value is already durable: the two attempt ladders count in
        ``onboarding_run_state``, and the standing disposition of each reservation
        says whether an effect was skipped as a duplicate or left ambiguous. Read
        once, at the end of the walk, so the outcome reports the run rather than the
        turn.

        A store that cannot answer leaves the counter at zero rather than failing
        the walk: the outcome is the record of a run that has already finished, and
        losing it to a metrics read would be the worse trade.
        """

        try:
            self.verification_attempts = deps.phases.verification_attempts(run_id=run_id)
            self.validation_attempts = deps.phases.validation_attempts(run_id=run_id)
        except Exception:  # pragma: no cover - a read failure carries no count
            LOGGER.info("onboarding run %s attempt counters were unreadable", run_id)
        self.outcome_unknown_effects = sum(
            1
            for record in _standing_reservations(run_id=run_id, deps=deps)
            if record.disposition == "pause_outcome_unknown"
        )


def _standing_reservations(
    *, run_id: str, deps: OnboardingDeps, phase: OnboardingPhase | None = None
) -> tuple[EffectReservationRecord, ...]:
    """The run's standing reservations, optionally narrowed to one phase.

    An unwired reader yields nothing, which is the honest answer rather than a
    guess: the counters that read this report zero, and no other behaviour depends
    on it.
    """

    reader = deps.effects
    if reader is None:
        return ()
    try:
        records = reader.reservations(run_id=run_id)
    except Exception:  # pragma: no cover - a read failure carries no reservations
        LOGGER.info("onboarding run %s effect reservations were unreadable", run_id)
        return ()
    if phase is None:
        return records
    return tuple(record for record in records if record.phase == phase)


# The two decision causes a raised chain can report, kept apart because they ask
# different things of the operator: a transport failure is a quota or an outage,
# an unusable payload is a provider that answered badly (R4.5, R4.6). The third
# cause — no provider key configured — is named where the chain is built, by
# ``ops.onboarding.composition.DECIDER_UNAVAILABLE`` (R4.4).
_DECISION_PAUSE_REASONS: Final[dict[DecisionReasonCode, OnboardingReasonCode]] = {
    "rate_limited": "decision_provider_failed",
    "authentication_failed": "decision_provider_failed",
    "provider_timeout": "decision_provider_failed",
    "all_providers_failed": "decision_provider_failed",
    "invalid_json": "decision_unusable",
    "schema_invalid": "decision_unusable",
}


def step_for_decision_failure(failure: DecisionFailed) -> PhaseStep:
    """Pause naming which decision cause stopped the phase (R4.5, R4.6, R4.11)."""

    return PhaseStep.pause(
        _DECISION_PAUSE_REASONS.get(failure.reason_code, "decision_provider_failed")
    )


def step_for_loop_result(phase: OnboardingPhase, result: LoopResult) -> PhaseStep:
    """Map one loop outcome onto the transition the driver should commit.

    The loop classifies; this decides. Four outcomes, four answers:

    * ``done`` advances into the successor declared for the phase.
    * ``gate`` advances into ``captcha_paused`` when the page named a CAPTCHA,
      which is the only mid-flight operator prompt that exists (Requirement
      11.1); any other typed human action pauses, and its disposition belongs to
      the gate-resolution seam.
    * ``exhausted`` pauses carrying the reason code the loop returned, which is
      Requirement 4.15 read literally — the driver does not invent a code for a
      bound the loop already named.
    * ``denied_fatal`` pauses carrying the denial code: repeated attempts to
      leave the allow-list are a containment event, not a slow phase.
    """

    if result.outcome == "done":
        successor = PHASE_SUCCESSORS.get(phase)
        if successor is None:
            raise PhaseNotDrivable(phase, "no successor is declared for a completed loop phase")
        return PhaseStep.advance(successor, result.reason_code)
    if result.outcome == "gate" and result.observation.human_action_type == "captcha":
        return PhaseStep.advance("captcha_paused", result.reason_code)
    return PhaseStep.pause(result.reason_code)


def is_duplicate_account_reroute(boundary: PhaseTransition | None) -> bool:
    """Whether ``boundary`` is the autonomous duplicate-account re-route.

    Read from a committed boundary rather than from a flag a worker held, so a
    run that crashed after the re-route was committed is recognised as a
    re-routed run when the next worker resumes it (Requirements 6.7, 6.8).
    """

    if boundary is None:
        return False
    return (
        boundary.from_phase == DUPLICATE_ACCOUNT_REROUTE_SOURCE
        and boundary.to_phase == DUPLICATE_ACCOUNT_REROUTE_TARGET
        and boundary.reason_code == DUPLICATE_ACCOUNT_REROUTE
    )


def adopt_signup_references_for_login(
    *, run_id: str, profile_digest: str, deps: OnboardingDeps
) -> tuple[tuple[str, str], ...]:
    """Reuse the run's stored signup references as its login references (6.8).

    PRE:  the ``signup -> route_selected_login`` boundary carrying
          :data:`DUPLICATE_ACCOUNT_REROUTE` is durably committed, so the phase the
          references are adopted for is already a fact.
    POST: the run's login references are bound and non-empty, and no operator
          prompt was emitted — the whole recovery is a vault read and a rebind.

    An empty binding, or a binder that was never wired, is a defect on this side
    rather than a run outcome: the signup phase stores the pair before it submits,
    so a re-route with nothing to sign in with means the storage guarantee broke.
    It is raised rather than paused, because a pause here would put an operator in
    a loop the requirement says has no operator in it.
    """

    binder = deps.logins
    if binder is None:
        raise PhaseNotDrivable(
            DUPLICATE_ACCOUNT_REROUTE_TARGET,
            "the duplicate-account re-route has no login reference binder wired",
        )
    references = binder.adopt_signup_references_for_login(
        run_id=run_id, profile_digest=_profile_digest(profile_digest)
    )
    if not references:
        raise PhaseNotDrivable(
            DUPLICATE_ACCOUNT_REROUTE_TARGET,
            "the duplicate-account re-route found no stored signup references",
        )
    LOGGER.info(
        "onboarding run %s re-routed to login on %s under %d stored reference(s)",
        run_id,
        DUPLICATE_ACCOUNT_REROUTE,
        len(references),
    )
    return references


def resumption_phase(history: Sequence[PhaseTransition]) -> tuple[OnboardingPhase, int]:
    """Where a worker re-enters the walk, and the attempt counter that goes with it.

    The last committed boundary is the answer in the ordinary case: resuming
    earlier than it would redo work the ledger already records, which is what
    Requirement 12.10 forbids. Two cases are not ordinary.

    *A phase outside* :data:`~ops.onboarding.phase.RESUMABLE_PHASES` is a position
    no worker may re-enter — it names a transient computation rather than a place
    to stand — so the resumption phase is recomputed from the prior durable phase,
    walking back through the committed boundaries to the most recent one that *is*
    resumable (Requirement 12.13). Recomputing from history rather than guessing
    keeps the answer a durable fact.

    *A terminal phase* is reported as-is even though it too is outside the
    resumable set. Walking back from ``completed`` would hand the driver a phase to
    re-drive for a run that is finished; reporting the terminal phase instead lets
    the driver stop, which is the only correct behaviour there.

    An empty history means nothing has been committed, so the walk starts at
    :data:`~ops.onboarding.phase.INITIAL_PHASE` — research, which reserves no
    effect and therefore needs no boundary ahead of it.
    """

    if not history:
        return (INITIAL_PHASE, 0)
    last = history[-1]
    if last.to_phase in TERMINAL_PHASES or last.to_phase in RESUMABLE_PHASES:
        return (last.to_phase, last.attempt)
    for boundary in reversed(history[:-1]):
        if boundary.to_phase in RESUMABLE_PHASES:
            return (boundary.to_phase, boundary.attempt)
    return (INITIAL_PHASE, 0)


def has_entered_a_session(history: Sequence[PhaseTransition]) -> bool:
    """Whether the run is already past admission — past its first session phase.

    A run that is already there when planning is introduced keeps the behaviour it
    started with: nothing is planned for it and adherence stays inert, because a
    plan produced mid-walk would be compared against steps the run already took.
    """

    return any(boundary.to_phase in SESSION_BEARING_PHASES for boundary in history)


class RunPlanningPorts(Protocol):
    """The three pre-flight planning dependencies shared by both runtimes."""

    @property
    def plans(self) -> RunPlanStore | None: ...

    @property
    def planner(self) -> RunPlanner | None: ...

    @property
    def plan_validator(self) -> RunPlanValidator: ...


def _catalog_recipe(app_slug: str) -> AppRecipe | None:
    """The immutable Recipe_Catalog entry bound to ``app_slug``, if present."""

    return get_app_recipe(app_slug)


def _catalog_plan_refusal() -> PlanRefusal:
    """The fail-closed answer when admission has no catalog route to validate."""

    return PlanRefusal(
        reason_code=PLAN_REFUSAL_REASON_CODE,
        detail="recipe_route_not_browser",
        ordinal=CREDENTIAL_SURFACE_ORDINAL,
    )


def plan_admission(
    *,
    run_id: str,
    profile: ProviderProfile | None,
    deps: RunPlanningPorts,
    recipe: AppRecipe | None = None,
) -> PlanRefusal | None:
    """Produce, reuse, and validate a plan before the run's first session.

    An unwired plan store is deliberately inert: without durable plan state there
    is no honest expectation for route adherence to compare against.  With a store
    wired, an existing active plan is validated and reused before a planner is
    consulted, so re-queuing performs no second planning call.  A new run with no
    catalog recipe, an unplannable recipe, or any invalid planned surface is
    refused with ``plan_surface_not_in_catalog`` before session creation.
    """

    plans = deps.plans
    if plans is None:
        return None

    selected_recipe = recipe
    if selected_recipe is None and profile is not None:
        selected_recipe = _catalog_recipe(profile.app_slug)
    if selected_recipe is None:
        return _catalog_plan_refusal()

    existing = plans.read_active_plan(run_id=run_id)
    if existing is not None:
        return deps.plan_validator(existing, recipe=selected_recipe)

    planner = deps.planner
    if planner is None:
        # The storage port is the adherence authority.  If its producing port is
        # absent, leave the run unplanned rather than inventing a route here.
        return None

    outcome = planner.plan_for(recipe=selected_recipe, revision=1)
    if isinstance(outcome, PlanRefusal):
        return outcome

    refusal = deps.plan_validator(outcome.plan, recipe=selected_recipe)
    if refusal is not None:
        return refusal
    recorded = plans.record_initial_plan(
        run_id=run_id,
        plan=outcome.plan,
        reason_code=outcome.reason_code,
    )
    # A concurrent admission may have won the initial-plan race.  Validate the
    # durable winner rather than assuming it is the plan this caller proposed.
    return deps.plan_validator(recorded, recipe=selected_recipe)


def phase_correlation_id(*, run_id: str, phase: OnboardingPhase, attempt: int) -> str:
    """A bounded, deterministic correlation id for one phase attempt.

    Deterministic in the run, the phase, and the attempt, so two workers driving
    the same phase attempt derive the same id and the timeline of a retried
    phase can be read as one thread. Hashed rather than concatenated because a
    run id may be longer on its own than the correlation column admits.
    """

    seed = f"{run_id}|{phase}|{_attempt(attempt)}".encode()
    return sha256(seed).hexdigest()[:32]


async def drive_run(*, run_id: str, worker_id: str, deps: OnboardingDeps) -> AutonomyOutcome | None:
    """Advance one run under a lease until it blocks, pauses, or terminates.

    PRE:
      P1. ``run_id`` names an existing run; ``deps`` is fully wired.
      P2. no other worker holds a live lease for the run (the lease store's own
          guarantee, not an assumption this function makes).

    POST:
      Q1. the phase the run stopped at is terminal, is a waiting phase, or is the
          phase a deferral left committed.
      Q2. every boundary crossed was committed here, before the target phase's
          first effect was reserved — handlers and the loop commit nothing
          (Requirements 12.9, 4.20).
      Q3. the lease is released exactly once, on every exit path, which the
          guard's context manager rather than this body guarantees.
      Q4. ``None`` is returned when the lease was not claimable — another worker
          owns the run, which is a normal outcome and not an error.
      Q5. a run that stopped at a terminal phase has exactly one
          :class:`AutonomyOutcome` recorded for it, whether this call or an
          earlier one wrote it; a run that paused, deferred, or was fenced out has
          none, because it has not reached its outcome yet (Requirement 20.4).

    INVARIANTS:
      I1. ownership is confirmed at the top of every iteration; a lost fencing
          token stops the walk before any further effect (Requirement 16.6).
      I2. the profile the run is attributable to is loaded once, by the digest
          the phase history recorded, and is identical across every iteration.
      I3. the walk resumes at the last committed phase, never earlier
          (Requirement 12.10), unless that phase is one no worker may stand in,
          in which case :func:`resumption_phase` recomputes it from the prior
          durable phase (Requirement 12.13).
      I4. a run that reached ``route_selected_login`` through the duplicate-account
          re-route has its stored signup references adopted as login references
          before the phase is driven, and that recovery emits no operator prompt
          (Requirements 6.7, 6.8).
      I5. a run entering its first session-bearing phase has a validated plan
          recorded before any session exists, or is planned inertly; a plan the
          catalog does not declare pauses the run there with
          ``plan_surface_not_in_catalog`` and no session (Requirements 5.1, 5.6).
    """

    lease = deps.leases.claim(
        run_id=run_id, worker_id=worker_id, ttl_seconds=deps.timings.ttl_seconds
    )
    if lease is None:  # Q4
        LOGGER.info("onboarding run %s is already leased by another worker", run_id)
        return None

    started = deps.clock()
    tally = _RunTally()
    # One read of the durable history answers both questions below — where to
    # resume (I3) and under which profile (I2) — so the two cannot disagree.
    history = deps.phases.history(run_id=run_id)
    phase, attempt = resumption_phase(history)  # I3
    # A phase is durable when a committed boundary put the run there. Only the
    # very first entry into ``research`` is not, and research reserves no effect.
    phase_is_durable = bool(history)
    profile = _load_profile(history=history, run_id=run_id, deps=deps)
    reason_code: OnboardingReasonCode = NO_STEP_TAKEN
    # A run standing at ``route_selected_login`` because signup found the account
    # already existed still has to have its stored signup references adopted as
    # login references before the phase is driven (I4). Derived from the committed
    # boundary, so a crash between the commit and the adoption is recovered here.
    reroute_pending = is_duplicate_account_reroute(history[-1] if history else None)
    # Admission is the moment before the run's first session-bearing phase (I5).
    # A run already past it is left unplanned.
    planning_settled = has_entered_a_session(history)

    with LeaseGuard(
        store=deps.leases, lease=lease, timings=deps.timings, clock=deps.clock
    ) as guard:
        while phase not in TERMINAL_PHASES and phase not in WAITING_PHASES:
            check = guard.before_step()  # I1
            if not check.may_drive:
                break
            held = check.lease
            assert held is not None  # RenewalCheck carries a lease iff it may drive

            if phase in EFFECT_BEARING_PHASES and phase_is_durable:
                # Requirement 20.5's duplicate-skip count, read from the standing
                # dispositions rather than reported by the handler: entering an
                # effect-bearing phase whose reservation already stands at ``skip``
                # is exactly the duplicate the ledger prevented — the effect
                # happened, and this entry will adopt its receipt instead of
                # submitting again (Requirement 13.6).
                tally.effects_skipped_as_duplicate += sum(
                    1
                    for record in _standing_reservations(run_id=run_id, deps=deps, phase=phase)
                    if record.disposition == "skip"
                )

            if phase in EFFECT_BEARING_PHASES and not phase_is_durable:
                # Q2 as a refusal rather than a comment: entering a phase that
                # reserves a provider-visible effect without a durable boundary
                # into it would make the reservation the first durable fact, and a
                # crash would then leave an effect no phase owns.
                raise PhaseNotDrivable(
                    phase, "its effect may not be reserved before its boundary is committed"
                )

            if reroute_pending and phase == DUPLICATE_ACCOUNT_REROUTE_TARGET:
                # I4: the login route is driven from references, so they are bound
                # before the handler runs and never as a side effect of it. The
                # adoption is idempotent, so re-driving the phase re-binds the same
                # references and emits no prompt (Requirement 6.8).
                if profile is None:
                    raise PhaseNotDrivable(phase, "the run has no committed provider profile")
                adopt_signup_references_for_login(
                    run_id=run_id, profile_digest=profile.profile_digest, deps=deps
                )
                reroute_pending = False

            refusal: PlanRefusal | None = None
            if phase in SESSION_BEARING_PHASES and not planning_settled:
                # I5: the plan exists before the first session does, because this
                # runs ahead of ``_drive_phase``, which is what creates one.
                refusal = plan_admission(run_id=run_id, profile=profile, deps=deps)
                planning_settled = True

            step = (
                PhaseStep.pause(refusal.reason_code)
                if refusal is not None
                else await _drive_phase(
                    run_id=run_id, phase=phase, profile=profile, lease=held, deps=deps, tally=tally
                )
            )
            reason_code = step.reason_code

            if step.kind == "yield":
                # A deferral is a scheduling fact: nothing is committed, and the
                # run comes back at the phase it is already at.
                assert step.not_before is not None
                deps.queue.defer(run_id=run_id, not_before=step.not_before)
                break

            target = step.next_phase or "paused"
            digest = step.profile_digest or (profile.profile_digest if profile else None)
            if digest is None:
                raise PhaseNotDrivable(phase, "a phase transition requires a profile digest")
            # Q2: the one place a boundary becomes durable.
            if deps.phases.commit_phase(
                run_id=run_id,
                from_phase=phase,
                to_phase=target,
                reason_code=step.reason_code,
                profile_digest=digest,
                attempt=attempt,
                correlation_id=phase_correlation_id(run_id=run_id, phase=phase, attempt=attempt),
            ):
                if target == "captcha_paused":
                    # Requirement 11.3: one prompt per committed captcha pause.
                    tally.captcha_prompts += 1
                elif target == ADMISSION_PROMPT_PHASE:
                    # Requirement 11.13: the admission prompt belongs to the one
                    # boundary into ``awaiting_admission``, which is reachable only
                    # from ``vault_check`` and therefore crossed at most once —
                    # a replayed boundary lands in the branch below instead. The
                    # emission itself is authorized durably by
                    # :func:`emit_admission_prompt`; this is the accounting.
                    tally.admission_prompts = ADMISSION_PROMPT_LIMIT
            else:
                # A replay found the boundary already durable, which is exactly
                # the precondition the next iteration needs.
                tally.phases_replayed += 1
            if (
                phase == DUPLICATE_ACCOUNT_REROUTE_SOURCE
                and target == DUPLICATE_ACCOUNT_REROUTE_TARGET
                and step.reason_code == DUPLICATE_ACCOUNT_REROUTE
            ):
                # Requirement 6.7 is the boundary above; 6.8 is what the next
                # iteration does with it, and it is armed here on the committed and
                # the replayed path alike.
                reroute_pending = True
            phase = target
            phase_is_durable = True
            if profile is None or profile.profile_digest != digest:
                # The research phase is where the digest first exists; from then
                # on I2 holds because no later step supplies a different one.
                profile = deps.profiles.get(profile_digest=digest) or profile

    ended = deps.clock()
    # The four counters that belong to the run rather than to this turn, read once
    # from the durable ladders and reservations (Requirement 20.5).
    tally.adopt_durable_counters(run_id=run_id, deps=deps)
    outcome = AutonomyOutcome(
        run_id=run_id,
        profile_digest=profile.profile_digest if profile else "",
        verdict=autonomy_verdict(phase=phase, captcha_prompts=tally.captcha_prompts),
        terminal_phase=phase,
        reason_code=reason_code,
        started_at=_moment(started),
        ended_at=_moment(ended),
        duration_seconds=max(int((ended - started).total_seconds()), 0),
        admission_prompts=tally.admission_prompts,
        captcha_prompts=tally.captcha_prompts,
        model_calls=tally.model_calls,
        actions_executed=tally.actions_executed,
        navigation_denials=tally.navigation_denials,
        phases_replayed=tally.phases_replayed,
        effects_skipped_as_duplicate=tally.effects_skipped_as_duplicate,
        outcome_unknown_effects=tally.outcome_unknown_effects,
        verification_attempts=tally.verification_attempts,
        validation_attempts=tally.validation_attempts,
    )
    if phase in TERMINAL_PHASES:  # Q5
        _record_autonomy_outcome(outcome=outcome, deps=deps, attempt=attempt)
    return outcome


def _record_autonomy_outcome(
    *, outcome: AutonomyOutcome, deps: OnboardingDeps, attempt: int = 0
) -> None:
    """Write the run's one autonomy outcome, at a terminal phase only (20.4).

    Called on the terminal path and nowhere else, because a run that paused or was
    fenced out has not reached its outcome yet: recording one then would count a
    run that is still going to be driven again.

    Write-once is the store's, not this function's — a second arrival at the same
    terminal phase is reported as a replay and discarded, so the first record
    stands. That is also why a replay is logged rather than raised: the run really
    is terminal, and the only new information is that somebody had already said so.
    """

    # Requirement 20.1: the nine identifiers are assembled once, from the durable
    # record and the attempt the walk ended on, and every log line about this
    # outcome carries all of them. Built here rather than inlined per line so a
    # line cannot quietly omit one.
    correlation = OnboardingCorrelation.for_outcome(
        outcome.as_record(),
        attempt=attempt,
        correlation_id=phase_correlation_id(
            run_id=outcome.run_id, phase=outcome.terminal_phase, attempt=attempt
        ),
    )
    context = correlation.as_log_fields()
    store = deps.outcomes
    if store is None:
        LOGGER.info(
            "onboarding run %s terminated at %s with no autonomy outcome store wired",
            outcome.run_id,
            outcome.terminal_phase,
            extra=context,
        )
        return
    if store.record_autonomy_outcome(outcome=outcome):
        LOGGER.info(
            "onboarding run %s recorded autonomy outcome %s at %s after %d second(s)",
            outcome.run_id,
            outcome.verdict,
            outcome.terminal_phase,
            outcome.duration_seconds,
            extra=context,
        )
        # The structured line the metrics and the timeline read the same nine
        # fields off. The verdict and the counts ride along as outcomes, never as
        # page content: every value here is a closed vocabulary member or a count.
        correlation.emit(
            "onboarding.autonomy_outcome",
            verdict=outcome.verdict,
            duration_seconds=outcome.duration_seconds,
            admission_prompts=outcome.admission_prompts,
            captcha_prompts=outcome.captcha_prompts,
            model_calls=outcome.model_calls,
            actions_executed=outcome.actions_executed,
            navigation_denials=outcome.navigation_denials,
            phases_replayed=outcome.phases_replayed,
        )
        return
    LOGGER.info(
        "onboarding run %s already had an autonomy outcome recorded; keeping the first",
        outcome.run_id,
        extra=context,
    )


def autonomy_verdict(*, phase: OnboardingPhase, captcha_prompts: int) -> AutonomyVerdict:
    """The verdict for a run that stopped at ``phase``.

    A completed run with no CAPTCHA pause is the only fully autonomous outcome;
    a completed run that needed one is operator-assisted. Everything else is
    named by the phase it stopped at, and a run that stopped short of a terminal
    phase is operator-assisted because a human or a timer now owns it.
    """

    if phase == "cancelled":
        return "cancelled"
    if phase == "blocked":
        return "blocked"
    if phase == "completed":
        return "fully_autonomous" if captcha_prompts == 0 else "operator_assisted"
    return "operator_assisted"


# --- the verification service ------------------------------------------------
#
# Email verification is the phase most onboarding systems hand back to a human.
# It stays autonomous here (design LL-3.4), which means the system reads a
# mailbox and puts what it finds into a live provider page. Five properties are
# the reason the code below looks the way it does.
#
# Every decision about *which message* is already written down elsewhere.
# ``ops.email.verification`` owns recipient binding, sender authentication,
# freshness, secret extraction, and link-host confinement, and
# ``select_verification`` applies all of them in one pass. This service supplies
# the *bounds* those rules are applied with — the run's own mailbox alias, the
# run's allow-list, the freshness floor — and reads back a decision plus a stable
# reason code. Re-deciding any of it here would be a second place a binding rule
# could be forgotten (Requirements 7.6 - 7.13).
#
# The mailbox is a port, never a vendor. Nothing here names Gmail: the provider
# arrives as ``VerificationProvider``, and an unwired or unconfigured one is a
# pause with ``verification_unresolved`` and zero consumed messages
# (Requirement 7.3) rather than an error, because "no mailbox" is a deployment
# state and not a run failure.
#
# Exactly-once is the vault's, and a claim is released on every failure path.
# ``claim`` / ``release`` / ``settle`` are the provider's verbs over the vault's
# ``UNIQUE`` reservation, so a contended claim is a deferral
# (``verification_claim_contended``) rather than a second consumption, and an
# unaccepted verification releases the claim so a later attempt can spend the
# same still-valid code (Requirements 7.16 - 7.22).
#
# The one-time value exists in this process for exactly one injection. A link is
# navigated on the run's own session; a code goes through the transient-grant
# path — into the vault, then out as a reference plus a one-shot grant the browser
# process redeems — so the value crosses one boundary only and never reaches a
# log, a prompt, a checkpoint, an audit row, or an API body (Requirements 7.31,
# 7.32, Property 4).
#
# Verification continues, it does not restart. The session port has no login verb
# and no navigation verb beyond the resolved link, so "submit the login form 0
# additional times" (Requirement 7.30) is structural rather than promised, and the
# session id is checked to be the run's bound one before anything is claimed.

VERIFICATION_PHASE: Final[OnboardingPhase] = "email_verification"

# What the run is waiting for. The onboarding walk reaches verification straight
# out of signup, so the purpose is the signup confirmation rather than a login
# code; the vocabulary is ``ops.email.verification``'s, not a local string.
VERIFICATION_PURPOSE: Final[VerificationPurpose] = "signup_confirmation"

VERIFICATION_ACCEPTED: Final[OnboardingReasonCode] = "verification_email_found"
VERIFICATION_UNRESOLVED: Final[OnboardingReasonCode] = "verification_unresolved"
VERIFICATION_CLAIM_CONTENDED: Final[OnboardingReasonCode] = "verification_claim_contended"
VERIFICATION_LINK_BLOCKED: Final[OnboardingReasonCode] = "verification_link_blocked"

# The postcondition that decides whether the provider accepted the verification.
# Read from the phase's declared postconditions through ``check_postconditions``
# rather than re-tested here, so this service cannot lower the phase's own bar.
VERIFICATION_POSTCONDITION: Final = "verification_completed"

# The two shapes a resolved verification can take, named from
# ``ops.email.verification``'s vocabulary so the branch below is a comparison
# against the type the selector reported rather than against a local string.
VERIFICATION_LINK: Final[VerificationSecretKind] = "link"

# The backoff ceiling and the jitter window of Requirement 7.25. Jitter is
# half-open on purpose — two workers deferring the same run must not be able to
# land on the same instant by both drawing the maximum.
VERIFICATION_BACKOFF_CAP_SECONDS: Final = 30.0
VERIFICATION_JITTER_MIN: Final = 0.8
VERIFICATION_JITTER_MAX: Final = 1.2

# The transient vault kind a resolved one-time code is staged under, and the
# field name the grant's operation key is suffixed with. Reused from the four
# one-shot login kinds that already exist at the broker boundary — onboarding adds
# none — so the code is redeemable only through the path built for a one-time fill.
VERIFICATION_CODE_FIELD: Final = "login_otp"
VERIFICATION_CODE_KIND: Final = f"{TRANSIENT_LOGIN_KIND_PREFIX}{VERIFICATION_CODE_FIELD}"

# A verification code is short-lived and is injected once, so the shortest TTL the
# vault admits is the right one.
VERIFICATION_CODE_TTL_SECONDS: Final = 300

# Import-time proof that the staged kind is one the broker already admits. A kind
# outside that set would be unredeemable, which is a wiring defect worth finding
# at import rather than while a live provider page waits for a code.
assert VERIFICATION_CODE_KIND in TRANSIENT_LOGIN_VAULT_KINDS, (
    "a verification code is staged under one of the existing one-shot login kinds"
)


@dataclass(frozen=True, slots=True)
class VerificationBudget:
    """The bounds one verification ladder runs under. Configuration, not literals.

    ``max_attempts`` is where the ladder stops rather than polls forever
    (Requirement 7.28), ``base_delay_seconds`` feeds the bounded jittered backoff
    (Requirement 7.25), and ``freshness_seconds`` is the rolling window a
    candidate message must clear — bounded at
    :data:`~ops.email.verification.MAX_VERIFICATION_AGE_SECONDS` by Requirement
    7.11, which is enforced here rather than trusted.
    """

    base_delay_seconds: float = 5.0
    max_attempts: int = 3
    freshness_seconds: int = MAX_VERIFICATION_AGE_SECONDS

    def __post_init__(self) -> None:
        if self.base_delay_seconds < 0:
            raise ValueError("the verification base delay cannot be negative")
        if self.max_attempts < 1:
            raise ValueError("the verification attempt budget is at least one attempt")
        if not 0 < self.freshness_seconds <= MAX_VERIFICATION_AGE_SECONDS:
            raise ValueError(
                f"the verification freshness window is bounded at "
                f"{MAX_VERIFICATION_AGE_SECONDS} seconds"
            )

    @classmethod
    def from_settings(cls, settings: Settings) -> VerificationBudget:
        """The deployment's configured verification bounds (Requirements 7.11, 7.26, 7.27)."""

        return cls(
            base_delay_seconds=float(settings.onboarding_verification_base_delay_seconds),
            max_attempts=int(settings.onboarding_verification_attempt_budget),
            freshness_seconds=int(settings.onboarding_verification_max_message_age_seconds),
        )


@dataclass(frozen=True, slots=True)
class VerificationContext:
    """The durable facts one verification attempt is bound to. Carries no secret.

    ``mailbox_address`` is the alias the run signed up with, plus-tag included: the
    single fact that prevents one run from consuming another run's verification, so
    it is required rather than derived. ``session_id`` is the session that
    submitted signup and is still alive — verification continues there
    (Requirement 7.30). ``challenge_issued_at_ms`` is when this run's verification
    challenge was recorded (the committed ``email_verification`` boundary), which
    is the floor a newly issued challenge is admitted against.
    """

    mailbox_address: str
    session_id: str
    challenge_issued_at_ms: int
    # Message ids this run already consumed. Passed to the selector so a settled
    # message is never re-examined even before the claim ladder is reached.
    consumed_message_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if canonical_address(self.mailbox_address) is None:
            raise ValueError("a verification context requires the run's mailbox address")
        _identifier(self.session_id, field="browser session id")
        if self.challenge_issued_at_ms <= 0:
            raise ValueError("the verification challenge timestamp is a positive epoch instant")


class VerificationSession(Protocol):
    """The live session verification is completed on, and nothing more.

    Deliberately narrow: there is no login verb and no free navigation verb here,
    which is how "continue on the same ``Browser_Session_ID`` and submit the login
    form 0 additional times" (Requirement 7.30) is a property of the port rather
    than a promise in a comment. The only value that crosses is a resolved link,
    and a code crosses as a reference plus a one-shot grant.
    """

    @property
    def session_id(self) -> str:
        """The bound session's id, which verification must not change."""

    async def navigate_verification_link(self, link: SecretStr) -> None:
        """Open one resolved verification link on this session.

        PRE:  the link's host is inside the run's allow-list (checked by the
              caller through ``is_safe_verification_link``).
        POST: the value is used once and never returned, logged, or persisted.
        """

    async def inject_one_time_code(self, *, reference: str, kind: str, grant: str) -> None:
        """Fill one one-time code through the transient-grant path.

        PRE:  ``grant`` authorizes exactly one ``consume`` of ``reference`` for
              this run and this session.
        POST: the code is resolved inside the browser process only; no value
              crosses this call (Requirement 7.32).
        """

    async def observe(self) -> LoopObservation:
        """The page's bounded observation after the injection."""


class VerificationSecretVault(Protocol):
    """The two vault verbs a one-time code injection needs, and no others.

    Structurally satisfied by :class:`ops.core.secret_store.SQLiteSecretStore`, and the
    same pair the signup phase stages its fills with. There is no read verb, so
    this service cannot resolve back what it just staged.
    """

    def put_transient(
        self, *, app_slug: str, kind: str, scope_id: str, value: str, ttl_seconds: int = 600
    ) -> str:
        """Store one one-time, run-scoped value and return its reference."""

    def reserve_browser_secret_grant(
        self,
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: Literal["consume", "capture"],
        reference: str | None = None,
        ttl_seconds: int = 900,
    ) -> str:
        """Reserve one exact broker operation and return its opaque grant."""


class VerificationBinding(Protocol):
    """Where the driver learns which mailbox and which session a run verifies on.

    Two verbs, both read-only. The context carries the run's own mailbox alias —
    the single fact that stops one run consuming another run's verification — and
    the session verb hands back the session that submitted signup, so verification
    continues there rather than logging in again (Requirement 7.30). There is no
    verb here that could create a mailbox, mint an address, or open a second
    session.
    """

    def verification_context(
        self, *, run_id: str, challenge_issued_at_ms: int
    ) -> VerificationContext:
        """The run's mailbox alias, bound session, and freshness floor."""

    async def verification_session(self, *, run_id: str, lease: Lease) -> VerificationSession:
        """The still-alive session the signup submission was made on."""


def verification_backoff_seconds(
    *, budget: VerificationBudget, attempt: int, jitter: float | None = None
) -> float:
    """``base * 2**attempt``, capped at 30 s, times jitter in [0.8, 1.2) (7.25).

    The cap is applied before the jitter so the jitter cannot push a delay past
    the ceiling, and the exponent is the attempt already consumed, which makes the
    sequence monotonically non-decreasing in ``attempt`` and bounded by the cap
    (invariant I3).
    """

    if jitter is None:
        # Half-open by construction: ``random.random()`` is [0.0, 1.0).
        jitter = VERIFICATION_JITTER_MIN + random.random() * (
            VERIFICATION_JITTER_MAX - VERIFICATION_JITTER_MIN
        )
    if not VERIFICATION_JITTER_MIN <= jitter < VERIFICATION_JITTER_MAX:
        raise ValueError("the verification jitter factor is in [0.8, 1.2)")
    delay: float = min(
        budget.base_delay_seconds * 2.0 ** _attempt(attempt), VERIFICATION_BACKOFF_CAP_SECONDS
    )
    return delay * jitter


def verification_query(
    *,
    profile: ProviderProfile,
    context: VerificationContext,
    budget: VerificationBudget,
) -> VerificationQuery:
    """The run-bound, freshness-bounded, secret-free query for one attempt.

    Every bound comes from a durable fact: the mailbox alias binds the query to
    this run (Requirement 7.4), the profile's own domain set is the sender hint,
    the run's allow-list travels with the query so the navigation site cannot
    re-derive a wider one (Requirement 7.14), and the freshness floor is the
    recorded challenge instant — which never moves backwards across attempts
    (invariant I1).
    """

    return VerificationQuery(
        expected_recipient=context.mailbox_address,
        sender_domains=_verification_sender_domains(profile),
        purpose=VERIFICATION_PURPOSE,
        not_before_ms=context.challenge_issued_at_ms,
        max_age_seconds=budget.freshness_seconds,
        allowed_link_hosts=profile.allowed_hosts().patterns(),
    )


async def await_verification(
    *,
    run_id: str,
    profile: ProviderProfile,
    provider: VerificationProvider | None,
    session: VerificationSession,
    vault: VerificationSecretVault,
    context: VerificationContext,
    attempt: int,
    budget: VerificationBudget,
    clock: Callable[[], datetime] = _utc_moment,
) -> PhaseStep:
    """Resolve one provider verification message and consume it exactly once.

    ``attempt`` is the number of verification attempts this run has already
    consumed, so the first call passes zero and the ladder stops when it reaches
    ``budget.max_attempts`` (Requirement 7.28).

    PRE:
      P1. the run is in phase ``email_verification`` (durably committed by the
          driver, which is the only committer).
      P2. ``session`` is the session that submitted signup and is still active.
      P3. ``profile`` is the run's committed profile, so the allow-list the link
          is judged against is the run's own.

    POST:
      Q1. on success the message was claimed exactly once across all processes and
          attempts, and the claim was settled before returning (Requirement 7.21).
      Q2. the one-time value existed in this process for one injection only: it
          reaches no phase step, no log, no checkpoint, no audit row, and no API
          body (Requirement 7.31).
      Q3. any navigated link satisfied ``is_safe_verification_link`` against the
          run's allow-list; anything else released the claim and paused with
          ``verification_link_blocked`` (Requirements 7.14, 7.15).
      Q4. the session id after the injection is the session id before it, and no
          login form was submitted again (Requirement 7.30).
      Q5. on exhaustion the run pauses with ``verification_unresolved``; it never
          loops unbounded and never advances on a guess.

    INVARIANTS:
      I1. a candidate is examined only while it binds to the run's mailbox and its
          receive time clears the recorded challenge instant; the freshness floor
          never moves backwards across attempts.
      I2. at most one claim is held at a time, and it is released on every failure
          path so a later attempt can claim the same message.
      I3. the deferral is ``min(base * 2**attempt, 30 s) * jitter``.
    """

    if attempt >= budget.max_attempts:
        # Q5: the ladder terminates on the durable counter, not on a worker's
        # patience, so a crashed-and-resumed run cannot restart the budget.
        LOGGER.info("onboarding run %s exhausted its verification attempt budget", run_id)
        return PhaseStep.pause(VERIFICATION_UNRESOLVED)
    if provider is None or not provider.is_configured():
        # Requirement 7.3: no mailbox means no search and no claim, so the run's
        # consumed-message count stays at zero.
        LOGGER.info("onboarding run %s has no configured verification provider", run_id)
        return PhaseStep.pause(VERIFICATION_UNRESOLVED)
    if session.session_id != context.session_id:
        # Q4 checked before anything is claimed: a different session would mean a
        # re-login, which this phase never performs.
        raise PhaseNotDrivable(
            VERIFICATION_PHASE, "verification continues on the run's bound browser session"
        )

    now = clock()
    now_ms = int(now.timestamp() * 1000)
    query = verification_query(profile=profile, context=context, budget=budget)
    candidates = await provider.search(query)
    decision = select_verification(
        candidates,
        purpose=query.purpose,
        expected_recipient=query.expected_recipient,
        now_ms=now_ms,
        max_age_seconds=query.max_age_seconds,
        allowed_host_patterns=query.allowed_link_hosts,
        reviewed_sender_patterns=_verification_reviewed_senders(profile),
        # Requirements 7.6 - 7.9: only an exact or canonical recipient binding and
        # aligned DMARC/DKIM/SPF (or validated ARC) evidence may be accepted.
        require_reviewed_sender=True,
        require_authenticated_sender=True,
        require_reviewed_link_host=True,
        consumed_message_ids=context.consumed_message_ids,
        # Requirement 7.13 through the selector's own 30 s tolerance; the floor is
        # also Requirement 7.10's run-start bound (I1). Future-dating past 300 s is
        # refused by the selector's clock-skew bound (Requirement 7.12).
        verification_requested_at_ms=context.challenge_issued_at_ms,
        clock_skew_seconds=DEFAULT_CLOCK_SKEW_SECONDS,
        request_clock_skew_seconds=VERIFICATION_REQUEST_CLOCK_SKEW_SECONDS,
    )
    if not decision.is_resolved:
        # Requirements 7.7 and 7.9 ask for the rejection to be recorded. The codes
        # are the selector's closed vocabulary — no address, subject, or body.
        LOGGER.info(
            "onboarding run %s found no qualifying verification message: %s (examined %d, %s)",
            run_id,
            decision.reason_code,
            decision.examined,
            ",".join(decision.rejections) or "no rejections",
        )
        return _verification_deferral(
            budget=budget, attempt=attempt, now=now, reason_code=VERIFICATION_UNRESOLVED
        )

    resolved = decision.resolved
    assert resolved is not None  # decision.is_resolved
    evidence = resolved.evidence
    reservation = await provider.claim(message_id=evidence.message_id, run_id=run_id)
    if reservation.status == "busy":
        # Requirement 7.18: another caller holds the claim, so this attempt leaves
        # the message unconsumed and comes back later.
        return _verification_deferral(
            budget=budget, attempt=attempt, now=now, reason_code=VERIFICATION_CLAIM_CONTENDED
        )
    if reservation.status == "completed":
        # Requirement 7.24: this run already consumed the message on an earlier
        # attempt, so the provider-side verification already happened. Advance
        # rather than verify a second time.
        return PhaseStep.advance(PHASE_SUCCESSORS[VERIFICATION_PHASE], VERIFICATION_ACCEPTED)
    claim_token = reservation.claim_token
    assert claim_token is not None  # an acquired reservation carries its token

    try:
        if evidence.verification_kind == VERIFICATION_LINK:
            link = resolved.secret.get_secret_value()
            safe = is_safe_verification_link(link, query.allowed_link_hosts)
            del link
            if not safe:
                # Q3: a link outside the run's allow-list is a containment event,
                # and the claim is released so nothing is consumed by it.
                await provider.release(
                    message_id=evidence.message_id, run_id=run_id, claim_token=claim_token
                )
                LOGGER.warning(
                    "onboarding run %s refused a verification link outside its allow-list", run_id
                )
                return PhaseStep.pause(VERIFICATION_LINK_BLOCKED)
            await session.navigate_verification_link(resolved.secret)
        else:
            reference, grant = _stage_verification_code(
                vault=vault,
                profile=profile,
                context=context,
                run_id=run_id,
                message_id=evidence.message_id,
                code=resolved.secret,
            )
            # Q2 / Requirement 7.32: from here on this process holds a reference
            # and a one-shot grant, and the value resolves inside the browser.
            await session.inject_one_time_code(
                reference=reference, kind=VERIFICATION_CODE_KIND, grant=grant
            )

        observed = await session.observe()
        accepted = _verification_accepted(profile=profile, observation=observed.observation)
        if not accepted or session.session_id != context.session_id:
            # Requirement 7.20 (I2): release rather than settle, so a code that is
            # still valid stays claimable by the next attempt.
            await provider.release(
                message_id=evidence.message_id, run_id=run_id, claim_token=claim_token
            )
            return _verification_deferral(
                budget=budget, attempt=attempt, now=now, reason_code=VERIFICATION_UNRESOLVED
            )
        # Q1 / Requirement 7.21: settle before returning, so no later caller can
        # spend the same one-time secret.
        await provider.settle(
            message_id=evidence.message_id, run_id=run_id, claim_token=claim_token
        )
        return PhaseStep.advance(PHASE_SUCCESSORS[VERIFICATION_PHASE], VERIFICATION_ACCEPTED)
    finally:
        # Q2: the only references this process held to the value go away on every
        # path, including the exceptional one.
        del resolved, decision


def _verification_deferral(
    *,
    budget: VerificationBudget,
    attempt: int,
    now: datetime,
    reason_code: OnboardingReasonCode,
) -> PhaseStep:
    """A yielding step at ``now + backoff(attempt)`` (Requirements 7.19, 7.25)."""

    delay = verification_backoff_seconds(budget=budget, attempt=attempt)
    return PhaseStep.defer(_moment(now + timedelta(seconds=delay)), reason_code)


def _verification_accepted(*, profile: ProviderProfile, observation: BrowserObservation) -> bool:
    """Whether the page reports the provider accepted the verification.

    The bar is the phase's own declared postcondition, checked through
    ``check_postconditions`` against a fresh observation, so this service reads
    the same rule the action loop does instead of inventing a weaker one.
    """

    goal = PhaseGoal.for_phase(
        VERIFICATION_PHASE,
        provider_name=profile.provider_name,
        description="Complete the provider's email verification for this run.",
        instruction="Confirm the provider accepted the verification the mailbox supplied.",
        success_reason_code=VERIFICATION_ACCEPTED,
    )
    check = check_postconditions(goal, observation)
    return VERIFICATION_POSTCONDITION in check.satisfied


def _stage_verification_code(
    *,
    vault: VerificationSecretVault,
    profile: ProviderProfile,
    context: VerificationContext,
    run_id: str,
    message_id: str,
    code: SecretStr,
    ttl_seconds: int = VERIFICATION_CODE_TTL_SECONDS,
) -> tuple[str, str]:
    """Put one resolved code into the vault and take back a reference and a grant.

    POST: returns ``(reference, grant)`` and no value. The operation key is
          deterministic in the run and the immutable message id, so a retried
          injection redeems the same grant rather than minting a second one.
    """

    reference = vault.put_transient(
        app_slug=profile.app_slug,
        kind=VERIFICATION_CODE_KIND,
        scope_id=run_id,
        value=code.get_secret_value(),
        ttl_seconds=ttl_seconds,
    )
    grant = vault.reserve_browser_secret_grant(
        operation_key=_verification_operation_key(run_id=run_id, message_id=message_id),
        run_id=run_id,
        session_id=context.session_id,
        app_slug=profile.app_slug,
        kind=VERIFICATION_CODE_KIND,
        action="consume",
        reference=reference,
        ttl_seconds=ttl_seconds,
    )
    return (reference, grant)


def _verification_operation_key(*, run_id: str, message_id: str) -> str:
    """The broker operation key for one message's single code injection.

    The message id is hashed rather than embedded: a provider id may carry
    characters the broker's key grammar refuses, and the hash is still
    deterministic in the message, which is what makes a retry redeem the same
    grant.
    """

    digest = sha256(message_id.encode("utf-8")).hexdigest()[:32]
    return f"{run_id}:verification:{digest}:consume:{VERIFICATION_CODE_FIELD}"


def _verification_sender_domains(profile: ProviderProfile) -> tuple[str, ...]:
    """The profile's own domain plus any host it declared for email links."""

    hosts = tuple(
        auxiliary.host
        for auxiliary in profile.auxiliary_hosts
        if auxiliary.kind == "email_link_host"
    )
    return tuple(dict.fromkeys((profile.registrable_domain, *hosts)))


def _verification_reviewed_senders(profile: ProviderProfile) -> tuple[str, ...]:
    """The sender patterns a verification message may legitimately come from.

    The profile's single registrable domain and its subdomains, plus any declared
    email-link host. Providers send verification mail from a sending subdomain far
    more often than from the bare domain, so the wildcard is the useful entry — and
    it is still one domain, which is what keeps the profile the authority.
    """

    domains = _verification_sender_domains(profile)
    return tuple(dict.fromkeys((*domains, *(f"*.{domain}" for domain in domains))))


# --- the developer-application service ---------------------------------------
#
# Between an authenticated session and a credential sits the page every provider
# builds differently: the developer console's "create an application" flow. A
# provider the repo has never seen has no reviewed recipe for it, so what drives
# this phase is the profile's own ``FlowSpec`` (design LL-3.5, Requirement 9.2).
# Five properties are the reason the code below looks the way it does.
#
# The flow is chosen by what the run needs, then checked against what the
# provider offers. ``CREDENTIAL_FLOW_KINDS`` maps the requested credential kind
# onto the flow that produces it, and the phase needs *two* flows to be
# supported: the developer-application flow it walks, and the flow that will mint
# the credential afterwards. Either one declared unsupported is a pause with
# ``flow_unsupported`` and no reservation (Requirements 9.3, 9.10) — the run
# stops before it creates an application no credential can come out of.
#
# A gate is answered before anything is reserved, never after. Approval and
# billing requirements are read off the profile (and off the selected flows,
# which state the same thing at finer grain) and turned into a pause *above* the
# reservation, so a run parked on ``developer_app_approval_required`` or
# ``billing_required`` holds no operation key at all (Requirements 9.7, 9.8). An
# ``unknown`` requirement is deliberately absent from both blocking sets: it
# proceeds, and the sanitized projection reports it verbatim as ``unknown``
# rather than as ``none`` (Requirement 9.9).
#
# The requested application name is derived, never invented. ``developer_app_name``
# is a pure function of the owner identity and the run identity, so two workers
# driving this phase request the same application and derive one operation key
# (Requirement 9.4) — and the key itself folds in the profile digest, the flow
# kind, and the canonicalized entry URL through
# :func:`ops.onboarding.effects.create_dev_app_key` (Requirement 9.5). No clock,
# attempt number, worker id, or session id participates in either.
#
# The application id is read from the page's own observation, not from the model.
# ``done`` is only returned when the phase's declared postcondition
# ``developer_app_present`` holds, which is exactly "the observation carries a
# developer application id", and that id is what the effect completion records as
# its non-secret receipt (Requirement 9.6). A phase that did not reach ``done``
# records nothing: the reservation stays open, so the next arrival reconciles
# rather than creating a second application (Requirement 13.7).
#
# The advance this service asks for is ``credential_generation``, and the driver
# commits it before the generation effect is reserved (Requirement 9.11) — which
# holds because the driver refuses to enter an effect-bearing phase whose
# boundary is not already durable.

DEVELOPER_APP_PHASE: Final[OnboardingPhase] = "developer_app"

# The provider-visible effect this phase reserves, read from the driver's own
# table rather than restated, so the phase and its effect cannot be paired two
# different ways in two places.
DEVELOPER_APP_EFFECT: Final[OnboardingEffect] = EFFECT_BEARING_PHASES[DEVELOPER_APP_PHASE]

DEVELOPER_APP_CREATED: Final[OnboardingReasonCode] = "developer_app_created"
DEVELOPER_APP_APPROVAL_REQUIRED: Final[OnboardingReasonCode] = "developer_app_approval_required"
DEVELOPER_APP_BILLING_REQUIRED: Final[OnboardingReasonCode] = "billing_required"

# The provider offers no drivable flow for what this run needs. Distinct from
# ``capture_spec_unavailable`` on purpose (open item 5): an operator reading this
# has to choose a different credential kind or a different provider, not re-run
# the phase.
DEVELOPER_APP_FLOW_UNSUPPORTED: Final[OnboardingReasonCode] = "flow_unsupported"

# The run has no committed profile, so neither the allow-list nor the operation
# key can be derived. Recoverable by re-research, which is what this code means.
DEVELOPER_APP_PROFILE_UNAVAILABLE: Final[OnboardingReasonCode] = "capture_spec_unavailable"

# The requirement values that stop the phase before it reserves anything.
# ``unknown`` is absent from both, and that absence is Requirement 9.9.
BLOCKING_APPROVAL_REQUIREMENTS: Final[frozenset[ApprovalRequirement]] = frozenset(
    {"manual_review", "invite_only"}
)
BLOCKING_BILLING_REQUIREMENTS: Final[frozenset[BillingRequirement]] = frozenset(
    {"card_required", "paid_plan_required"}
)

# Import-time proof that both sets are drawn from the profile's own vocabularies
# and that neither blocks on ``unknown``. A typo here would silently stop gating,
# which is the kind of defect worth finding at import.
assert BLOCKING_APPROVAL_REQUIREMENTS <= APPROVAL_REQUIREMENTS, (
    "every blocking approval requirement must be a declared approval requirement"
)
assert BLOCKING_BILLING_REQUIREMENTS <= BILLING_REQUIREMENTS, (
    "every blocking billing requirement must be a declared billing requirement"
)
assert "unknown" not in BLOCKING_APPROVAL_REQUIREMENTS | BLOCKING_BILLING_REQUIREMENTS, (
    "an unknown approval or billing requirement proceeds (Requirement 9.9)"
)

# The requested credential kind -> the flow kind that produces it. This is how
# Requirement 9.3's four flows are reached: the OAuth application flow, the API
# key flow, the personal access token flow, and the client credentials flow are
# each selected by the credential the run asked for, and a profile that declares
# none of them for that credential pauses rather than guessing.
CREDENTIAL_FLOW_KINDS: Final[dict[CredentialKind, FlowKind]] = {
    "oauth_client_id": "oauth",
    "oauth_client_secret": "oauth",  # pragma: allowlist secret
    "api_key": "api_key",  # pragma: allowlist secret
    "personal_access_token": "pat",
    "client_credentials_pair": "client_credentials",
}

# Import-time totality: every credential kind the profile vocabulary admits has a
# flow that produces it, so no requested kind can fall through to a guess.
assert set(CREDENTIAL_FLOW_KINDS) == set(get_args(CredentialKind)), (
    "every credential kind must name the flow kind that produces it"
)

# The receipt key the completed reservation records the application id under.
# Reused from the credential lifecycle rather than re-spelled, so the phase that
# writes the id and the phase that reads it (task 17.2) cannot disagree — and so
# the key stays one the ledger's redaction grammar admits.
DEVELOPER_APP_RECEIPT_KEY: Final = CAPTURE_RECEIPT_DEVELOPER_APP_ID

# The non-secret flow identifier the same receipt carries, so an operator reading
# the ledger can see which declared flow created the application.
DEVELOPER_APP_RECEIPT_FLOW_KEY: Final = "flow_kind"

# The reviewed, non-secret value reference the application-name field is filled
# from. The loop authorizes a reference, never literal text, and the browser
# process resolves it from immutable run state — so the name a provider page
# receives is never model output and never a clock.
DEVELOPER_APP_NAME_REF: Final = "application_name"

assert DEVELOPER_APP_NAME_REF in APPROVED_VALUE_REFS, (
    "the application name must be a reviewed non-secret value reference"
)

# The shape of the name the run asks the provider for: a fixed prefix plus a
# digest over the owner and the run. The digest rather than the owner's own
# identifier is deliberate — an owner id may be an email address, and this string
# is typed into a third party's application list.
DEVELOPER_APP_NAME_PREFIX: Final = "composio-ops"
DEVELOPER_APP_NAME_DIGEST_LENGTH: Final = 12


@dataclass(frozen=True, slots=True)
class DeveloperAppRequest:
    """What this run wants out of the developer-application phase.

    Both fields are durable run facts rather than page-derived ones, which is
    what lets the requested name and therefore the operation key be derived
    identically by any worker that picks the run up.
    """

    owner_id: str
    credential_kind: CredentialKind

    def __post_init__(self) -> None:
        _identifier(self.owner_id, field="owner id")
        if self.credential_kind not in CREDENTIAL_FLOW_KINDS:
            raise ValueError("credential kind is not a declared onboarding credential kind")


@dataclass(frozen=True, slots=True)
class DeveloperAppFlows:
    """The two flows one developer-application phase is driven from.

    ``creation`` is the flow walked now; ``credential`` is the flow the next phase
    will mint from. Both are checked for support before either is walked, because
    an application created for a credential the provider will not issue is an
    unrepeatable effect spent for nothing.
    """

    creation: FlowSpec
    credential: FlowSpec

    def entry_urls(self) -> tuple[str, ...]:
        """The reviewed URLs a ``goto`` candidate may use in this phase."""

        return tuple(
            dict.fromkeys(
                url for url in (self.creation.entry_url, self.credential.entry_url) if url
            )
        )

    def signals(self) -> tuple[str, ...]:
        """The declared, non-secret step prose the prompt is grounded in."""

        return tuple(dict.fromkeys((*self.creation.steps, *self.credential.steps)))[:MAX_FLOW_STEPS]


class DeveloperAppBinding(Protocol):
    """Where the phase learns the run's owner and the credential it is after.

    Narrow on purpose: there is no verb here that could return a credential, a
    page, or a provider identifier, so the only thing this port can influence is
    which declared flow is selected and what the requested name digests over.
    """

    def developer_app_request(self, *, run_id: str) -> DeveloperAppRequest:
        """The run's durable developer-application request."""


def developer_app_name(*, owner_id: str, run_id: str) -> str:
    """The application name this run asks the provider for (Requirement 9.4).

    PRE:  ``owner_id`` and ``run_id`` are bounded identifiers.
    POST: pure in the owner and the run — no clock, counter, attempt number,
          worker id, session id, or page text participates — so two workers
          driving this phase request one application and
          :func:`ops.onboarding.effects.create_dev_app_key` derives one operation
          key from it.
    """

    owner = _identifier(owner_id, field="owner id")
    run = _identifier(run_id, field="run id")
    digest = sha256(f"{owner}|{run}".encode()).hexdigest()[:DEVELOPER_APP_NAME_DIGEST_LENGTH]
    return f"{DEVELOPER_APP_NAME_PREFIX}-{digest}"


def developer_app_gate(
    profile: ProviderProfile, *, flows: Sequence[FlowSpec] = ()
) -> OnboardingReasonCode | None:
    """The reason this phase must stop before it reserves anything, or ``None``.

    Approval is checked before billing so a provider that gates on both reports
    the one an operator can act on first. A flow's own ``requires_approval`` /
    ``requires_billing`` is the same claim the profile-level requirement makes,
    stated per flow, so both are read here rather than only the coarser one.

    ``unknown`` is not a gate (Requirement 9.9): the run proceeds, and the value
    travels to the sanitized projection unchanged.
    """

    if profile.approval_requirement in BLOCKING_APPROVAL_REQUIREMENTS:
        return DEVELOPER_APP_APPROVAL_REQUIRED
    if profile.billing_requirement in BLOCKING_BILLING_REQUIREMENTS:
        return DEVELOPER_APP_BILLING_REQUIRED
    if any(flow.requires_approval for flow in flows):
        return DEVELOPER_APP_APPROVAL_REQUIRED
    if any(flow.requires_billing for flow in flows):
        return DEVELOPER_APP_BILLING_REQUIRED
    return None


def developer_app_flows(
    profile: ProviderProfile, *, credential_kind: CredentialKind
) -> DeveloperAppFlows | None:
    """The supported flow pair for this credential kind, or ``None`` (9.3, 9.10).

    ``None`` means the provider declares no drivable path for what the run needs:
    either the developer-application flow is unsupported, or the flow that would
    produce the requested credential is unsupported or absent from the profile
    altogether. The caller pauses with :data:`DEVELOPER_APP_FLOW_UNSUPPORTED` and
    reserves nothing.

    The credential flow is looked up by the ``kind`` each declared ``FlowSpec``
    carries rather than by the profile field it happens to sit in, which is what
    makes the client-credentials flow reachable: the profile has four flow slots
    and five flow kinds, so "which flow is this" is a property of the spec, not of
    its position.
    """

    creation = profile.developer_app_flow
    if not creation.supported:
        return None
    wanted = CREDENTIAL_FLOW_KINDS[credential_kind]
    for flow in profile.flows():
        if flow.kind == wanted and flow.supported:
            return DeveloperAppFlows(creation=creation, credential=flow)
    return None


def developer_app_goal(
    *, profile: ProviderProfile, request: DeveloperAppRequest, flows: DeveloperAppFlows
) -> PhaseGoal:
    """The goal this phase is driven toward, built from the declared flows (9.2).

    Built here rather than taken from ``deps.goals`` because the reviewed URLs
    this phase may navigate to are the *selected* flows' entry URLs, and which
    flows are selected depends on the requested credential kind — something a
    factory keyed by phase and profile cannot know. The postconditions still come
    from :data:`~ops.onboarding.action_loop.PHASE_POSTCONDITIONS`, so the bar for
    ``done`` is the phase's declared one and this function cannot lower it.
    """

    return PhaseGoal.for_phase(
        DEVELOPER_APP_PHASE,
        provider_name=profile.provider_name,
        description=(
            "Create a developer application on this provider so the run can then be issued "
            f"a {request.credential_kind} credential."
        ),
        instruction=(
            "Create the provider's developer application through its own declared flow, "
            "filling only the approved application name."
        ),
        success_reason_code=DEVELOPER_APP_CREATED,
        signals=flows.signals(),
        reviewed_goto_urls=flows.entry_urls(),
        allow_value_refs=(DEVELOPER_APP_NAME_REF,),
    )


async def drive_developer_app(
    *,
    run_id: str,
    profile: ProviderProfile | None,
    request: DeveloperAppRequest,
    lease: Lease,
    effects: EffectStore,
    deps: OnboardingDeps,
) -> PhaseStep:
    """Create this run's one developer application and report the transition.

    PRE:
      P1. the ``developer_app`` boundary is durably committed — the driver refuses
          to enter an effect-bearing phase otherwise — so the reservation below is
          never the first durable fact about the phase that owns it
          (Requirements 9.1, 12.4).
      P2. ``profile`` is the run's committed profile, so the allow-list the loop is
          confined to and the operation key both come from one immutable artifact.

    POST:
      Q1. at most one developer application exists for this run: the key is pure
          in durable facts, so a retry, a second worker, and a resumed run all
          derive it and only one of them is authorized to execute
          (Requirements 9.4, 9.5).
      Q2. a returned ``advance`` into ``credential_generation`` implies the effect
          completion was recorded first, with a receipt carrying the non-secret
          developer application id (Requirements 9.6, 9.11).
      Q3. a pause for approval, for billing, or for an unsupported flow reserved
          no operation key and opened no browser session (Requirements 9.7, 9.8,
          9.10).
      Q4. nothing is committed here. The returned :class:`PhaseStep` is inert and
          the driver is the only committer (Requirement 4.20).

    INVARIANTS:
      I1. every gate is evaluated above the reservation, so no ordering of the
          branches below can leave a paused run holding a key.
      I2. the developer application id is read from the page's own observation,
          which the phase's postcondition already required to be present, and
          never from model output.
    """

    if profile is None:
        # Neither the allow-list nor the operation key can be derived without the
        # profile that names where the developer console is.
        return PhaseStep.pause(DEVELOPER_APP_PROFILE_UNAVAILABLE)

    # I1 / Q3: both answers below are reached with no key reserved and no session
    # opened, which is what Requirements 9.7, 9.8, and 9.10 ask for.
    flows = developer_app_flows(profile, credential_kind=request.credential_kind)
    if flows is None:
        LOGGER.info(
            "onboarding run %s has no supported developer-application flow for %s",
            run_id,
            request.credential_kind,
        )
        return PhaseStep.pause(DEVELOPER_APP_FLOW_UNSUPPORTED)
    gate = developer_app_gate(profile, flows=(flows.creation, flows.credential))
    if gate is not None:
        LOGGER.info("onboarding run %s cannot self-serve a developer application: %s", run_id, gate)
        return PhaseStep.pause(gate)

    # Derivation, not reservation: pure in the owner, the run, the profile digest,
    # the flow kind, and the canonicalized entry URL (Requirements 9.4, 9.5).
    requested_name = developer_app_name(owner_id=request.owner_id, run_id=run_id)
    operation_key = create_dev_app_key(run_id, profile, requested_name)
    plan = plan_effect(effects, operation_key=operation_key, action=DEVELOPER_APP_EFFECT)
    if plan.disposition == "skip":
        # Q1: an application already exists under this key. Adopt the recorded id
        # instead of creating a second one (Requirement 13.6).
        LOGGER.info(
            "onboarding run %s already created developer application %s",
            run_id,
            (plan.receipt or {}).get(DEVELOPER_APP_RECEIPT_KEY, "unrecorded"),
        )
        return PhaseStep.advance(PHASE_SUCCESSORS[DEVELOPER_APP_PHASE], DEVELOPER_APP_CREATED)
    if plan.disposition != "execute":
        # ``reconcile`` and ``pause_outcome_unknown`` both mean a prior attempt may
        # have reached the provider; neither authorizes a second one.
        return PhaseStep.pause(plan.reason_code)

    goal = developer_app_goal(profile=profile, request=request, flows=flows)
    session = await deps.sessions.session_for(run_id=run_id, phase=DEVELOPER_APP_PHASE, lease=lease)
    try:
        result = await run_action_loop(
            phase=DEVELOPER_APP_PHASE,
            goal=goal,
            session=session,
            allowed=profile.allowed_hosts(),
            budget=deps.budget,
            decider=deps.decider,
            telemetry=deps.telemetry,
            deadlines=deps.deadlines,
        )
    except DecisionFailed as failure:
        # The reservation stays open for the same reason it does below: nothing was
        # observed after the decision stopped.
        return step_for_decision_failure(failure)
    if result.outcome != "done":
        # The reservation is deliberately left open: a phase that stopped short may
        # still have created the application, so the next arrival reconciles rather
        # than creating a second one (Requirement 13.7). A CAPTCHA here takes the
        # same pause path every loop-driven phase takes.
        return await step_for_loop_outcome(
            run_id=run_id,
            phase=DEVELOPER_APP_PHASE,
            result=result,
            session=session,
            deps=deps,
        )

    # I2: ``done`` means the phase's ``developer_app_present`` postcondition held,
    # so the observation carries the id. A value that is not a bounded identifier
    # cannot be recorded, and an application that exists without a recorded id is
    # exactly an ambiguous outcome.
    developer_app_id = _developer_app_id(result.observation.developer_app_id)
    if developer_app_id is None:
        mark_effect_outcome_unknown(effects, plan)
        return PhaseStep.pause(OUTCOME_UNKNOWN)
    # Q2 / Requirement 9.6, before the phase advances: the receipt is what makes
    # every later arrival adopt this application instead of creating another.
    complete_effect(
        effects,
        plan,
        receipt={
            DEVELOPER_APP_RECEIPT_KEY: developer_app_id,
            DEVELOPER_APP_RECEIPT_FLOW_KEY: flows.creation.kind,
        },
    )
    LOGGER.info(
        "onboarding run %s created developer application %s through the %s flow",
        run_id,
        developer_app_id,
        flows.creation.kind,
    )
    return PhaseStep.advance(PHASE_SUCCESSORS[DEVELOPER_APP_PHASE], DEVELOPER_APP_CREATED)


@dataclass(frozen=True, slots=True)
class DeveloperAppPhaseHandler:
    """The ``developer_app`` phase, as a :class:`PhaseHandler`.

    Registered in ``OnboardingDeps.handlers`` under ``"developer_app"``, which is
    how a phase that reserves a provider-visible effect takes over from the
    generic loop dispatch: the loop alone would walk the page without ever
    reserving the key that makes a second application impossible.
    """

    effects: EffectStore
    binding: DeveloperAppBinding

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Drive one developer-application attempt and report its transition."""

        if phase != DEVELOPER_APP_PHASE:
            raise ValueError("the developer application handler drives that phase only")
        return await drive_developer_app(
            run_id=run_id,
            profile=profile,
            request=self.binding.developer_app_request(run_id=run_id),
            lease=lease,
            effects=self.effects,
            deps=deps,
        )


def _developer_app_id(value: str | None) -> str | None:
    """The observed application id as a bounded identifier, or ``None``.

    The ledger refuses an unbounded or secret-shaped receipt value, and a receipt
    that cannot be written must not raise out of a phase that has already created
    a real application — so a value this rejects becomes an ambiguous outcome
    rather than an exception.
    """

    if value is None:
        return None
    try:
        return _identifier(value, field="developer application id")
    except ValueError:
        LOGGER.warning("onboarding developer application id is not a recordable identifier")
        return None


def _developer_app_handler_conformance(handler: DeveloperAppPhaseHandler) -> PhaseHandler:
    """Typecheck-only proof that the handler satisfies the driver's port."""

    return handler


# --- the captcha pause and resume path ---------------------------------------
#
# One kind of popup exists while a run executes, and it means CAPTCHA (design
# LL-3.6, Requirement 11.1). That claim is only worth as much as the code that
# enforces it, so this section is written so the ways of breaking it are absent
# rather than discouraged.
#
# The set of prompting gates is a frozenset, and it is checked at import.
# :data:`MIDFLIGHT_OPERATOR_PROMPTS` has one member. Every other typed human
# action goes to :func:`midflight_gate_disposition`, which is a call into
# ``ops.access.gate_policy`` and nothing else — there is no prompt verb anywhere in this
# section that a second gate type could reach. The import-time assertions pin the
# member to a declared ``HumanActionType`` that the gate policy also holds
# permanently human-only, so "captcha is the only prompt" and "captcha is never
# auto-resolved" cannot drift apart.
#
# A pause records where it paused, and it does so before the boundary commits.
# ``pause_for_captcha`` writes the phase at pause and counts the prompt in one
# statement, then hands the driver an inert :class:`PhaseStep`. The ordering is
# what makes the resume total: a crash between the record and the commit leaves a
# recorded phase the run never paused at, which the resume path ignores because it
# refuses to run unless the committed phase *is* ``captcha_paused``. The reverse
# order would leave a committed pause with nowhere to resume to.
#
# The session survives the pause structurally, not by convention.
# :class:`PausedSession` has one member, a session id, so there is no verb on the
# pause path that could end a session or change its id — which is Requirement
# 11.4 and Property 11 read as a type rather than as a promise. The release verb
# exists only on :class:`ReleasableSession`, which only the cancel path takes.
#
# The budget is checked before the prompt, so exhaustion emits nothing.
# ``pause_for_captcha`` compares the *durable* count against the budget and
# returns a non-prompting ``paused`` step once it is reached (Requirements 11.10,
# 11.11). Nothing is recorded on that path, so a run parked on
# ``captcha_attempt_budget_exhausted`` cannot have its count nudged past the
# budget by repeated arrivals.
#
# A resume advances the attempt counter, and that is not cosmetic. The phase
# history's boundary uniqueness folds in the correlation id, which is derived from
# the run, the phase, and the attempt. Re-entering ``signup`` on the same attempt
# would make the *second* ``signup -> captcha_paused`` boundary a byte-for-byte
# replay of the first, swallowed as a no-op with the prompt count unchanged —
# exactly what Requirement 11.9 forbids. Advancing the attempt on re-entry makes
# each pass a distinct boundary.

# The one gate type that may reach an operator mid-flight. This frozenset is the
# whole of Requirement 11.1 and what design Property 10 asserts against.
MIDFLIGHT_OPERATOR_PROMPTS: Final[frozenset[HumanActionType]] = frozenset({"captcha"})

CAPTCHA_PAUSE_PHASE: Final[OnboardingPhase] = "captcha_paused"

CAPTCHA_DETECTED: Final[OnboardingReasonCode] = "captcha_detected"
CAPTCHA_RESOLVED: Final[OnboardingReasonCode] = "captcha_resolved"
CAPTCHA_BUDGET_EXHAUSTED: Final[OnboardingReasonCode] = "captcha_attempt_budget_exhausted"
# A cancelled resume is the operator's decision, so it carries the operator's own
# code rather than a captcha-shaped one: the run stopped because a person said so.
CAPTCHA_CANCELLED: Final[OnboardingReasonCode] = "operator_cancelled"

# Requirement 11.10: three pauses per run by default.
MAX_CAPTCHA_PAUSES: Final = 3

# What an operator can say about a CAPTCHA pause. Two answers, both terminal for
# the pause: there is no "retry" signal, because re-entering the phase and
# observing again *is* the retry.
CaptchaResumeSignal = Literal["completed", "cancelled"]
CAPTCHA_RESUME_SIGNALS: Final[tuple[CaptchaResumeSignal, ...]] = get_args(CaptchaResumeSignal)

# Import-time proof of the three things this section claims about its own prompt
# set. A prompting gate that is not a declared human action type could never be
# classified; one that the gate policy considers autonomously resolvable would be
# answered by a machine instead of a person; and the pre-execution admission
# decision is not a mid-flight gate at all.
assert MIDFLIGHT_OPERATOR_PROMPTS <= frozenset(get_args(HumanActionType)), (
    "every mid-flight operator prompt must be a declared human action type"
)
assert MIDFLIGHT_OPERATOR_PROMPTS <= HUMAN_ONLY_GATES, (
    "a gate that prompts an operator must never be autonomously resolvable"
)
assert "signup_authorization" not in MIDFLIGHT_OPERATOR_PROMPTS, (
    "the admission decision is a pre-execution prompt, not a mid-flight gate"
)

# The phases a CAPTCHA can interrupt: the session-bearing ones, minus the pause
# phase itself. Derived from ``SESSION_BEARING_PHASES`` rather than re-listed, so
# a phase that gains a browser session gains a pause path with it.
CAPTCHA_INTERRUPTIBLE_PHASES: Final[frozenset[OnboardingPhase]] = SESSION_BEARING_PHASES - {
    CAPTCHA_PAUSE_PHASE
}

# Import-time proof that every phase this section may pause from can reach both
# pause targets, and that every one of them can be re-entered from the pause. A
# missing row would surface as a refused transition against a live provider page
# with a challenge already on screen, which is the worst possible time to find it.
assert all(
    is_legal_phase_transition(phase, CAPTCHA_PAUSE_PHASE)
    and is_legal_phase_transition(phase, "paused")
    for phase in CAPTCHA_INTERRUPTIBLE_PHASES
), "every captcha-interruptible phase must admit both the captcha pause and a plain pause"
assert CAPTCHA_INTERRUPTIBLE_PHASES <= legal_phase_targets(CAPTCHA_PAUSE_PHASE), (
    "every captcha-interruptible phase must be re-enterable from the captcha pause"
)


@dataclass(frozen=True, slots=True)
class CaptchaBudget:
    """The bound on how many times one run may ask an operator to solve a CAPTCHA.

    A value rather than a literal for the same reason :class:`VerificationBudget`
    is: the number is policy, and a deployment that wants fewer prompts should be
    able to say so without editing the pause path.
    """

    max_pauses: int = MAX_CAPTCHA_PAUSES

    def __post_init__(self) -> None:
        if self.max_pauses < 0:
            raise ValueError("a captcha pause budget cannot be negative")


DEFAULT_CAPTCHA_BUDGET: Final = CaptchaBudget()


class CaptchaPauseStore(Protocol):
    """The two durable verbs the pause and resume path needs, and no others.

    Structurally satisfied by :class:`SQLitePhaseHistoryStore`, which already owns
    the ``onboarding_run_state`` projection these two columns live in. Declared as
    its own port rather than folded into :class:`PhaseHistoryStore` because the
    pause path needs no ability to commit a boundary — the driver commits, and a
    port that could do both would blur that.
    """

    def record_captcha_pause(self, *, run_id: str, phase_at_pause: OnboardingPhase) -> CaptchaPause:
        """Record the phase at pause and count this prompt, as one write.

        POST: the returned ``prompts`` is the run's count *including* this pause,
              so the caller never has to add one itself.
        """

    def captcha_pause(self, *, run_id: str) -> CaptchaPause:
        """The run's recorded phase at pause and its CAPTCHA prompt count."""


class PausedSession(Protocol):
    """The bound session a CAPTCHA pause holds open, and nothing more.

    One member, and that is the design: with no navigation verb, no act verb, and
    no release verb, a pause cannot end the session, cannot change its id, and
    cannot give away the capacity it holds (Requirement 11.4). The janitor's idle
    timer remains the only thing that may expire it.
    """

    @property
    def session_id(self) -> str:
        """The bound session's id, which a pause must not change."""


class ReleasableSession(PausedSession, Protocol):
    """A paused session plus the one verb the cancel path needs.

    Separated from :class:`PausedSession` so the release verb is reachable only
    from the branch that is allowed to use it (Requirement 11.12).
    """

    async def release(self) -> None:
        """Release the bound session and the capacity it holds."""


def midflight_gate_disposition(
    action_type: HumanActionType | None,
    *,
    app_slug: str,
    profile_authority: ProfileGateAuthority | None = None,
) -> GateResolution:
    """How a non-CAPTCHA mid-flight gate is disposed of, with no prompt (11.14).

    PRE:  ``action_type`` is not a member of :data:`MIDFLIGHT_OPERATOR_PROMPTS` —
          a CAPTCHA is paused for a person by :func:`pause_for_captcha`, and
          asking this function about one is a caller defect rather than a run
          outcome, so it is refused.
    POST: the answer is ``ops.access.gate_policy``'s, unmodified. ``"human_only"`` means
          the run pauses carrying the loop's own reason code, which
          :func:`step_for_loop_result` already does and which is drawn from the
          closed onboarding enumeration; anything else names the mechanism the
          gate-resolution seam resolves the gate through. Either way this function
          emits zero operator prompts, because there is no prompt verb it can
          reach.

    The seam is deliberately this thin. Which non-CAPTCHA gates may resolve
    without a human, under what per-gate budget, and with what escalation code is
    owned by the ``autonomous-gate-resolution`` spec; onboarding's whole
    obligation is to route the question there rather than answer it locally.
    """

    if action_type in MIDFLIGHT_OPERATOR_PROMPTS:
        raise ValueError("a captcha gate is paused for an operator, never delegated")
    return resolve_gate(action_type, app_slug=app_slug, profile_authority=profile_authority)


async def pause_for_captcha(
    *,
    run_id: str,
    phase_at_pause: OnboardingPhase,
    session: PausedSession,
    pauses: CaptchaPauseStore,
    budget: CaptchaBudget = DEFAULT_CAPTCHA_BUDGET,
) -> PhaseStep:
    """Pause one run on a CAPTCHA, keeping its session, and ask for the boundary.

    PRE:
      P1. ``phase_at_pause`` is a session-bearing phase the loop classified a
          CAPTCHA gate in, so it is one the phase machine admits a pause from.
      P2. no side effect is mid-flight: the loop returns ``gate`` *before* acting,
          never between a reservation and its completion.

    POST:
      Q1. the phase at pause is durable and this prompt is counted before the
          returned step is handed back, so the boundary the driver then commits
          into ``captcha_paused`` always has somewhere to resume to
          (Requirements 11.2, 11.3).
      Q2. the bound session is untouched: its id is unchanged and its capacity is
          still held (Requirement 11.4). Structural — :class:`PausedSession` has
          no verb that could do otherwise.
      Q3. once the run's prompt count has reached ``budget.max_pauses``, the
          returned step pauses with ``captcha_attempt_budget_exhausted`` and
          nothing is recorded, so no further prompt is emitted for the run
          (Requirement 11.11).
      Q4. nothing is committed here. The returned :class:`PhaseStep` is inert and
          the driver is the only committer (Requirements 12.9, 4.20).
    """

    if phase_at_pause not in CAPTCHA_INTERRUPTIBLE_PHASES:
        raise ValueError("a captcha pause is taken from a session-bearing phase")
    # Read, never written on this path: a bounded, non-secret id, checked so an
    # unusable session handle is refused before the pause becomes durable.
    session_id = _identifier(session.session_id, field="browser session id")
    taken = pauses.captcha_pause(run_id=run_id).prompts
    if taken >= budget.max_pauses:
        # Q3: the budget is compared before the prompt, so this branch records
        # nothing and the count cannot creep past the bound.
        LOGGER.info(
            "onboarding run %s exhausted its %d captcha pause(s) in phase %s",
            run_id,
            budget.max_pauses,
            phase_at_pause,
        )
        return PhaseStep.pause(CAPTCHA_BUDGET_EXHAUSTED)

    pause = pauses.record_captcha_pause(run_id=run_id, phase_at_pause=phase_at_pause)  # Q1
    LOGGER.info(
        "onboarding run %s paused on a captcha in phase %s (prompt %d of %d) on session %s",
        run_id,
        pause.phase_at_pause,
        pause.prompts,
        budget.max_pauses,
        session_id,  # Q2: read for the record, and the only thing this path may do
    )
    return PhaseStep.advance(CAPTCHA_PAUSE_PHASE, CAPTCHA_DETECTED)  # Q4


async def step_for_loop_outcome(
    *,
    run_id: str,
    phase: OnboardingPhase,
    result: LoopResult,
    session: PausedSession,
    deps: OnboardingDeps,
) -> PhaseStep:
    """:func:`step_for_loop_result`, with a CAPTCHA routed through the pause path.

    The classification is unchanged — a CAPTCHA still earns a boundary into
    ``captcha_paused`` — but the phase at pause is recorded and the prompt counted
    before the driver commits it, which is what gives the resume somewhere to go and
    the budget something to compare against (Requirements 11.2, 11.3, 11.10).

    With no pause store wired the plain classification stands: committing a pause
    whose phase was never recorded would leave a resume with nothing to re-enter,
    so an unwired deployment keeps the transition and loses only the durable count.
    """

    if (
        result.outcome == "gate"
        and result.observation.human_action_type in MIDFLIGHT_OPERATOR_PROMPTS
        and deps.pauses is not None
    ):
        return await pause_for_captcha(
            run_id=run_id,
            phase_at_pause=phase,
            session=session,
            pauses=deps.pauses,
            budget=deps.captcha_budget or DEFAULT_CAPTCHA_BUDGET,
        )
    return step_for_loop_result(phase, result)


async def resume_from_captcha(
    *,
    run_id: str,
    signal: CaptchaResumeSignal,
    session: ReleasableSession | None,
    deps: OnboardingDeps,
    pauses: CaptchaPauseStore,
) -> PhaseStep:
    """Return the run to the exact phase that paused, or cancel it.

    This is the one boundary the phase driver cannot commit: ``captcha_paused`` is
    a waiting phase, so ``drive_run`` stops at it and never re-enters. The resume
    path is therefore where the transition out of the pause becomes durable, and
    the returned :class:`PhaseStep` is the record of what was committed so the
    caller can re-queue the run without re-deciding anything.

    ``session`` is the reattached paused session, or ``None`` when no bound
    session is held any more. It is a required argument rather than an optional
    one so a caller has to state which of the two it has.

    PRE:
      P1. the run's last committed phase is ``captcha_paused``. Anything else is a
          caller defect — a resume signal for a run that is not paused on a
          CAPTCHA — and is refused rather than turned into a run outcome.
      P2. ``signal`` is a member of :data:`CAPTCHA_RESUME_SIGNALS`.

    POST:
      Q1. ``cancelled`` commits ``captcha_paused -> cancelled`` and releases the
          bound session, so the run holds no capacity afterwards
          (Requirement 11.12).
      Q2. ``completed`` commits re-entry into the *recorded* phase at pause, under
          an advanced attempt so a second pause from that phase is a new boundary
          rather than a swallowed replay (Requirements 11.8, 11.9). The action
          loop observes before it acts, which is a property of
          :func:`~ops.onboarding.action_loop.run_action_loop` rather than
          something this function arranges.
      Q3. the session id is unchanged on the ``completed`` path: nothing here
          touches the session, and the release verb is reachable only from Q1
          (Requirement 11.4, Property 11).
      Q4. a replayed resume commits nothing a second time and returns the same
          step, so an operator clicking twice costs the run nothing.
    """

    if signal not in CAPTCHA_RESUME_SIGNALS:
        raise ValueError("a captcha resume signal is `completed` or `cancelled`")
    # One read answers where the run stands, under which profile, and at which
    # attempt, so the three cannot disagree — the same reason ``drive_run`` reads
    # the history once.
    history = deps.phases.history(run_id=run_id)
    paused = history[-1] if history else None
    if paused is None or paused.to_phase != CAPTCHA_PAUSE_PHASE:  # P1
        raise PhaseNotDrivable(
            CAPTCHA_PAUSE_PHASE, "the run's last committed phase is not a captcha pause"
        )

    if signal == "cancelled":
        step = _commit_captcha_resume(
            run_id=run_id,
            target="cancelled",
            reason_code=CAPTCHA_CANCELLED,
            profile_digest=paused.profile_digest,
            attempt=paused.attempt,
            deps=deps,
        )
        if session is not None:  # Q1
            await session.release()
        LOGGER.info("onboarding run %s cancelled at a captcha pause by its operator", run_id)
        return step

    target = pauses.captcha_pause(run_id=run_id).phase_at_pause
    if target is None:
        # The pause records the phase before the boundary is committed, so a
        # committed pause with no recorded phase means that write was lost. There
        # is nothing to guess here and no operator question that would help, so it
        # is raised as the defect it is rather than paused.
        raise PhaseNotDrivable(
            CAPTCHA_PAUSE_PHASE, "the captcha pause recorded no phase to resume into"
        )
    step = _commit_captcha_resume(
        run_id=run_id,
        target=target,
        reason_code=CAPTCHA_RESOLVED,
        profile_digest=paused.profile_digest,
        # Q2: a new attempt, so the next pause from ``target`` is a distinct
        # boundary rather than a replay of the one that just resolved.
        attempt=paused.attempt + 1,
        deps=deps,
    )
    LOGGER.info(
        "onboarding run %s resumed from its captcha pause into phase %s on session %s",
        run_id,
        target,
        "reattached" if session is None else session.session_id,  # Q3
    )
    return step


def _commit_captcha_resume(
    *,
    run_id: str,
    target: OnboardingPhase,
    reason_code: OnboardingReasonCode,
    profile_digest: str,
    attempt: int,
    deps: OnboardingDeps,
) -> PhaseStep:
    """Commit one boundary out of ``captcha_paused`` and report it as a step.

    A replayed boundary is reported the same way it is committed (Q4 above): the
    store swallows it as a no-op, and the run is already where the step says it
    is, so the caller's next move is identical either way.
    """

    committed = deps.phases.commit_phase(
        run_id=run_id,
        from_phase=CAPTCHA_PAUSE_PHASE,
        to_phase=target,
        reason_code=reason_code,
        profile_digest=profile_digest,
        attempt=attempt,
        correlation_id=phase_correlation_id(
            run_id=run_id, phase=CAPTCHA_PAUSE_PHASE, attempt=attempt
        ),
    )
    if not committed:
        LOGGER.info(
            "onboarding run %s had already resumed from its captcha pause into %s (%s)",
            run_id,
            target,
            PHASE_REPLAY_NOOP,
        )
    return PhaseStep.advance(target, reason_code)


def _captcha_pause_store_conformance(store: SQLitePhaseHistoryStore) -> CaptchaPauseStore:
    """Typecheck-only proof that the SQLite store satisfies the pause port."""

    return store


# --- the prompt counters and the surfaces that are not prompts ----------------
#
# The pause path above answers "what happens when a CAPTCHA appears". This section
# answers the arithmetic question behind it: *how many* prompts a run has emitted,
# and why every other interruption a provider can render contributes zero
# (Requirements 11.5 - 11.7, 11.13, 11.15).
#
# There are exactly two counters, and both are durable columns.
# ``captcha_prompts`` is written by :meth:`SQLitePhaseHistoryStore.
# record_captcha_pause` — one increment per pause, which is what makes a
# re-observed challenge after a resume count again (Requirement 11.9) and what the
# budget in :func:`pause_for_captcha` compares against (Requirements 11.10,
# 11.11). ``admission_prompts`` is written by
# :meth:`SQLitePhaseHistoryStore.record_admission_prompt`, whose single
# conditional ``UPDATE`` is the at-most-once rule *and* the phase scoping: the row
# moves only from zero, and only while the committed phase is
# ``awaiting_admission``. A second click, a second worker, and a call from any
# other phase all match no row and authorize no prompt.
#
# Counting is separated from emitting on purpose. ``record_admission_prompt``
# returns how many prompts the caller may emit rather than a boolean, so
# :func:`emit_admission_prompt` cannot produce a prompt the count does not cover;
# the durable write is the authorization, not a note taken afterwards.
#
# Legal terms are accepted rather than escalated, and the authority is never the
# page. :func:`accept_legal_terms` asks ``ops.access.gate_policy`` — through the same
# :func:`midflight_gate_disposition` seam every non-CAPTCHA gate goes through —
# and accepts only on the ``recipe_declared`` or ``profile_declared`` answers,
# which are a reviewed catalog assertion and the run's own committed profile plus
# the operator's affirmative admission decision. The gate URL is additionally
# checked against the run's committed allow-list before the question is asked, so
# a terms dialog rendered on a redirected-to host is not accepted (Requirement
# 11.5). What is recorded is the *document*: its allow-listed URL with query and
# fragment dropped, and a SHA-256 digest of the text that was accepted, which is
# evidence of exactly what was agreed to without copying provider text into a
# durable row (Requirement 11.6).
#
# A cookie banner is not a prompt because it cannot be one. ``HumanActionType``
# declares no cookie or consent-banner member — asserted at import below — so a
# banner arrives as an ordinary executable candidate that the action loop clicks
# and classifies, and there is no branch on which it could reach an operator
# (Requirement 11.7). :func:`midflight_prompt_count` is the same statement as
# arithmetic: one prompt for a CAPTCHA, zero for every other classification and
# for an unclassified page.

# The gate a legal-terms surface is classified as, and the two authorities that
# may answer for it without a person. Derived from the gate policy's own
# vocabulary rather than restated, so an authority the policy stops granting stops
# being accepted here too.
LEGAL_ACCEPTANCE_GATE: Final[HumanActionType] = "legal_acceptance"
AUTONOMOUS_LEGAL_AUTHORITIES: Final[frozenset[GateResolution]] = frozenset(
    {"recipe_declared", "profile_declared"}
)

# The event type the accepted document is recorded under. One name, so the write
# and every later reader of the trail agree on it.
LEGAL_ACCEPTANCE_EVIDENCE: Final = "onboarding_legal_terms_accepted"

# A document digest is a SHA-256 hex content address, the same width every other
# digest in this feature is.
LEGAL_DOCUMENT_DIGEST_LENGTH: Final = SOURCE_DIGEST_LENGTH

# Import-time proof of the four things this section claims. The admission prompt
# is a real typed gate but not a mid-flight one; the legal gate is one the run's
# own profile may ever authorize, and never a prompting gate; and no cookie or
# consent banner is a typed human action at all, which is why dismissing one
# cannot cost an operator anything.
assert ADMISSION_GATE in get_args(HumanActionType), (
    "the admission prompt must be a declared human action type"
)
assert ADMISSION_GATE not in MIDFLIGHT_OPERATOR_PROMPTS, (
    "the admission prompt is emitted before execution, never mid-flight"
)
assert ADMISSION_PROMPT_LIMIT == 1, "a run asks for admission at most once"
assert LEGAL_ACCEPTANCE_GATE in PROFILE_DECLARABLE_GATES, (
    "legal acceptance must be authorizable by the run's own profile"
)
assert LEGAL_ACCEPTANCE_GATE not in MIDFLIGHT_OPERATOR_PROMPTS, (
    "a legal-terms surface is accepted, never surfaced to an operator"
)
assert not any("cookie" in action or "consent" in action for action in get_args(HumanActionType)), (
    "a cookie banner is not a typed human action, so it can never become a prompt"
)


@dataclass(frozen=True, slots=True)
class OperatorPrompts:
    """A run's whole operator-prompt account, read from its durable counters.

    ``other`` is a field rather than an omission so that Requirement 11.15 is
    representable and checkable: it is pinned to zero at construction, which is
    the same refusal :class:`AutonomyOutcome` makes, applied one layer earlier —
    at the point the counts are read rather than at the point they are recorded.
    """

    admission: int = 0
    captcha: int = 0
    other: int = 0  # MUST be 0 (Requirement 11.15)

    def __post_init__(self) -> None:
        if self.admission not in (0, ADMISSION_PROMPT_LIMIT):
            raise ValueError("the admission prompt is emitted at most once per run")
        if self.captcha < 0:
            raise ValueError("a captcha prompt count cannot be negative")
        if self.other != 0:
            raise ValueError(
                "an onboarding run emits no operator prompt beyond admission and captcha"
            )

    @property
    def total(self) -> int:
        """Every prompt the run has emitted, which is the two that may exist."""

        return self.admission + self.captcha


class AdmissionPromptStore(Protocol):
    """The two durable verbs the admission prompt needs, and no others.

    Its own port rather than a pair of methods on :class:`PhaseHistoryStore` for
    the same reason :class:`CaptchaPauseStore` is: emitting a prompt must not come
    with the ability to commit a phase. Structurally satisfied by
    :class:`SQLitePhaseHistoryStore`, which owns the projection the counter lives
    in.
    """

    def record_admission_prompt(self, *, run_id: str) -> int:
        """Count this admission prompt if the run is due one, and say how many.

        POST: the return value is the number of prompts the caller is authorized
              to emit — ``ADMISSION_PROMPT_LIMIT`` the first time the run stands
              at ``awaiting_admission``, and 0 for every later call and for a run
              standing at any other phase.
        """

    def admission_prompts(self, *, run_id: str) -> int:
        """How many admission prompts the run has emitted: 0 or 1."""


@dataclass(frozen=True, slots=True)
class AcceptedDocument:
    """What the run agreed to, in the only form worth keeping.

    The URL is the allow-listed page with its query and fragment dropped, and the
    digest is over the accepted text. Together they answer "which document, and
    was it this exact text" without the text itself becoming a durable row — the
    same trade the provider profile's per-claim excerpt digests make.
    """

    url: str
    document_digest: str
    document_length: int
    authority: GateResolution
    profile_digest: str
    phase: OnboardingPhase
    accepted_at: str

    def __post_init__(self) -> None:
        if not self.url.startswith("https://"):
            raise ValueError("an accepted document must be recorded from an https page")
        if len(self.document_digest) != LEGAL_DOCUMENT_DIGEST_LENGTH:
            raise ValueError("an accepted document digest must be a sha256 hex digest")
        if self.document_length <= 0:
            raise ValueError("an accepted document cannot be empty")
        if self.authority not in AUTONOMOUS_LEGAL_AUTHORITIES:
            raise ValueError("an accepted document must name the authority that accepted it")
        _profile_digest(self.profile_digest)
        _phase(self.phase)
        if not self.accepted_at:
            raise ValueError("an accepted document must carry its timestamp")

    def as_evidence(self) -> dict[str, object]:
        """The closed payload the evidence row carries. No page text, no secrets."""

        return {
            "url": self.url,
            "document_digest": self.document_digest,
            "document_length": self.document_length,
            "authority": self.authority,
            "profile_digest": self.profile_digest,
            "phase": self.phase,
            "accepted_at": self.accepted_at,
        }


class LegalEvidenceStore(Protocol):
    """Where an accepted legal document is recorded as durable evidence.

    One verb, and it takes an :class:`AcceptedDocument` rather than free-form
    fields, so nothing that is not part of the accepted-document record can be
    written through this port.
    """

    def record_legal_acceptance(self, *, run_id: str, document: AcceptedDocument) -> None:
        """Record the document this run accepted, for the run's timeline."""


@dataclass(frozen=True, slots=True)
class LegalAcceptance:
    """The outcome of meeting one legal-terms surface, prompts included.

    ``prompts`` is pinned to zero because both branches are promptless: an
    accepted surface never asks anyone, and a refused one pauses with a reason
    code that the gate-resolution seam owns (Requirements 11.5, 11.14). Keeping
    the field makes that a checkable count rather than a claim in a docstring.
    """

    accepted: bool
    authority: GateResolution
    document: AcceptedDocument | None = None
    prompts: int = 0

    def __post_init__(self) -> None:
        if self.prompts != 0:
            raise ValueError("accepting or refusing legal terms emits no operator prompt")
        if self.accepted != (self.document is not None):
            raise ValueError("an accepted surface carries its document, and a refused one none")
        if self.accepted and self.authority not in AUTONOMOUS_LEGAL_AUTHORITIES:
            raise ValueError("legal terms are accepted only under a declared authority")


def midflight_prompt_count(action_type: HumanActionType | None) -> int:
    """How many operator prompts one classified mid-flight surface emits.

    POST: 1 for a member of :data:`MIDFLIGHT_OPERATOR_PROMPTS`, which is the
          single gate type ``captcha``; 0 for every other typed human action, for
          a cookie banner or legal-terms surface (neither of which is a typed
          human action at all), and for an unclassified page (Requirements 11.7,
          11.14, 11.15).
    """

    return 1 if action_type in MIDFLIGHT_OPERATOR_PROMPTS else 0


def emit_admission_prompt(
    *, run_id: str, app_name: str, prompts: AdmissionPromptStore
) -> tuple[HitlRequest, ...]:
    """The run's one admission prompt, or nothing if it has already asked.

    PRE:  the run's committed phase is ``awaiting_admission`` — which this
          function does not trust the caller about, because the durable write it
          delegates to checks the phase itself.

    POST: Q1. exactly one ``signup_authorization`` prompt is returned the first
              time a run stands at ``awaiting_admission``, and the durable count
              is 1 before it is returned (Requirements 3.4, 11.13).
          Q2. every later call returns no prompt and writes nothing, so an
              operator refreshing the console, a re-queued worker, and a replayed
              boundary all cost the run zero further prompts.
          Q3. a run standing at any other phase returns no prompt, because the
              conditional write matched no row.
          Q4. nothing is committed here: this counts and composes, and the API
              delivers.
    """

    _identifier(run_id, field="run id")
    authorized = prompts.record_admission_prompt(run_id=run_id)
    if authorized == 0:  # Q2, Q3
        return ()
    LOGGER.info("onboarding run %s asked its operator to authorize account creation", run_id)
    return (admission_prompt(app_name),)  # Q1


def operator_prompts(
    *, run_id: str, prompts: AdmissionPromptStore, pauses: CaptchaPauseStore
) -> OperatorPrompts:
    """The run's prompt account as its durable counters describe it (11.15).

    Read rather than derived from a worker's tally, so the answer is the same for
    a run driven by one worker and a run passed between five.
    """

    _identifier(run_id, field="run id")
    return OperatorPrompts(
        admission=prompts.admission_prompts(run_id=run_id),
        captcha=pauses.captcha_pause(run_id=run_id).prompts,
    )


def accept_legal_terms(
    *,
    run_id: str,
    phase: OnboardingPhase,
    profile: ProviderProfile,
    admission: AdmissionDecision | None,
    gate_url: str,
    document_text: str,
    allowed: BrowserAllowedHosts,
    evidence: LegalEvidenceStore,
    accepted_at: str | None = None,
) -> LegalAcceptance:
    """Accept one legal-terms surface with no prompt, and record what was accepted.

    PRE:
      P1. ``profile`` is the run's committed profile and ``allowed`` is the
          allow-list derived from it, so "allow-listed page" means the same thing
          here as it does to the action loop.
      P2. ``admission`` is the run's recorded admission decision, or ``None`` for
          a run that has none. Page text is not an input: ``document_text`` is
          digested and never stored, logged, or classified against.

    POST:
      Q1. the surface is accepted only when its URL is on the run's allow-list and
          ``ops.access.gate_policy`` answers with a declared authority — a reviewed
          recipe or the run's own profile plus an affirmative operator admission
          (Requirement 11.5).
      Q2. an accepted surface records the document as evidence before this returns,
          carrying the sanitized URL and the digest of the accepted text
          (Requirement 11.6).
      Q3. both branches emit zero operator prompts, which
          :class:`LegalAcceptance` refuses to represent otherwise. A refusal is
          the caller's cue to pause under the gate-resolution seam, not to ask
          anyone (Requirement 11.14).
      Q4. nothing is committed here.
    """

    _identifier(run_id, field="run id")
    _phase(phase)
    if not document_text:
        raise ValueError("accepting legal terms requires the document that was accepted")
    here = evaluate_navigation(gate_url, allowed)
    if not here.allowed:  # Q1: an off-allow-list terms dialog is not ours to accept
        LOGGER.info(
            "onboarding run %s met a legal-terms surface outside its allow-list (%s)",
            run_id,
            here.reason_code,
        )
        return LegalAcceptance(accepted=False, authority="human_only")

    authority = (
        None
        if admission is None
        else ProfileGateAuthority(
            profile_digest=profile.profile_digest,
            registrable_domain=profile.registrable_domain,
            gate_url=gate_url,
            admission_route=admission.route,
            admission_decided_by=admission.decided_by,
            admission_profile_digest=admission.profile_digest,
        )
    )
    # The same seam every other non-CAPTCHA gate goes through, so this path cannot
    # grant itself an autonomy the policy withholds.
    resolution = midflight_gate_disposition(
        LEGAL_ACCEPTANCE_GATE, app_slug=profile.app_slug, profile_authority=authority
    )
    if resolution not in AUTONOMOUS_LEGAL_AUTHORITIES:  # Q3
        LOGGER.info(
            "onboarding run %s left a legal-terms surface undisposed in phase %s (%s)",
            run_id,
            phase,
            resolution,
        )
        return LegalAcceptance(accepted=False, authority=resolution)

    document = AcceptedDocument(
        # Query and fragment are dropped: a terms URL can carry a session token,
        # and evidence of the document does not need one.
        url=sanitize_url(gate_url),
        document_digest=sha256(document_text.encode("utf-8")).hexdigest(),
        document_length=len(document_text),
        authority=resolution,
        profile_digest=profile.profile_digest,
        phase=phase,
        accepted_at=accepted_at or _utc_now(),
    )
    evidence.record_legal_acceptance(run_id=run_id, document=document)  # Q2
    LOGGER.info(
        "onboarding run %s accepted the legal terms at %s under %s in phase %s",
        run_id,
        document.url,
        resolution,
        phase,
    )
    return LegalAcceptance(accepted=True, authority=resolution, document=document)


class AuditTrailLegalEvidence:
    """The accepted document, recorded through the existing redacting audit write.

    The onboarding timeline projects durable rows, and no table holds a legal
    acceptance yet — the run ledger's audit trail is the durable evidence surface
    that exists today, and it is reached through
    :meth:`ops.core.storage.OperationsStorage.append_audit_event`, the one write path
    key-aware redaction cannot be bypassed on. The payload is
    :meth:`AcceptedDocument.as_evidence`, which is closed by construction, so this
    adapter adds no field of its own.
    """

    def __init__(self, ledger: OperationsStorage) -> None:
        self._ledger = ledger

    def record_legal_acceptance(self, *, run_id: str, document: AcceptedDocument) -> None:
        """Append one evidence row for the document the run accepted."""

        self._ledger.append_audit_event(
            run_id=_identifier(run_id, field="run id"),
            event_type=LEGAL_ACCEPTANCE_EVIDENCE,
            payload=document.as_evidence(),
        )


def _admission_prompt_store_conformance(store: SQLitePhaseHistoryStore) -> AdmissionPromptStore:
    """Typecheck-only proof that the SQLite store satisfies the prompt port."""

    return store


def _autonomy_outcome_store_conformance(store: LedgerAutonomyOutcomes) -> AutonomyOutcomeStore:
    """Typecheck-only proof that the ledger recorder satisfies the port."""

    return store


def _autonomy_outcome_reader_conformance(store: LedgerAutonomyOutcomes) -> AutonomyOutcomeReader:
    """Typecheck-only proof that the same adapter satisfies the reader port.

    One adapter, two ports: the driver is handed the writer and the API's run
    detail projection is handed the reader, so neither can reach the other's verb.
    """

    return store


def _legal_evidence_conformance(recorder: AuditTrailLegalEvidence) -> LegalEvidenceStore:
    """Typecheck-only proof that the audit-trail recorder satisfies the port."""

    return recorder


# --- crash recovery with session reattach -------------------------------------
#
# A worker died, or the API process restarted. :func:`recover_run` is what the next
# worker calls to find out where the run stands, and design LL-3.7's whole claim
# about it is negative: recovery *reads*. It plans, and the plan is inert.
#
# Recovery commits no phase. It returns a :class:`RecoveryPlan`, and the only
# durable writes on the resumed run are the ones ``drive_run`` makes afterwards
# from the phase the plan names. That is why there is no ``commit_phase`` call
# anywhere below and no store verb reachable from this section that writes one:
# the phase-history port is used through ``history`` alone, and the effect port
# declared here (:class:`RecoveryEffectReader`) has exactly one read verb. A
# recovery that committed something would make crash recovery itself a source of
# durable facts a crash could then land inside (Requirement 16.11).
#
# No new research, and the same allow-list. The profile is loaded by the digest
# the run's last committed boundary recorded, through the same
# :func:`_load_profile` the driver uses, so the allow-list that authorized the
# actions before the crash is byte-for-byte the one that authorizes the next
# action (Requirements 16.9, 16.10). Recovery has no research port to call, so
# "performs no new research" is an absence rather than a promise, and the recorded
# digest is carried onto the plan unchanged.
#
# Reattach before create, in every session-bearing phase. A bound session that is
# still alive holds the run's authentication, its cookies, and its live view, so
# recovery asks for it first and keeps its id (Requirements 15.2, 15.4). Only when
# nothing can be reattached does a session get created, and then the plan says so:
# ``session_recreated`` plus ``reenter_phase_from_start``, because a fresh session
# is at the provider's front door rather than mid-phase (Requirement 15.5). The
# continuity event the reattach is recorded under is a member of
# :data:`RECOVERY_TRIGGERS`, which mirrors the two restart events the browser
# service's own continuity set names, so a reattach refreshes the session instead
# of racing the janitor.
#
# An authenticated phase that cannot reattach pauses instead of pretending. Once a
# run is past authentication, re-entering ``developer_app`` on an anonymous session
# would drive a logged-out console. Those phases are
# :data:`AUTHENTICATED_SESSION_PHASES`, and a failed reattach there produces a
# recoverable pause carrying ``session_unreattachable`` (Requirement 15.9) — the
# recoverable configuration state the design's status table already uses, never a
# failed run.
#
# An ambiguous effect is planned before a session is created, not after. Design
# LL-3.7 sketches the session first; the order here is reattach, then read the
# standing reservations, then create only if the run is actually going to
# continue. A run whose ledger already says ``pause_outcome_unknown`` is going to
# stop, and creating a browser session for it would spend capacity on a run that
# will not use it. The reattached session is still reported on that pause, because
# a paused run keeps its session (Requirement 11.4 applies to every pause, not
# just the CAPTCHA one).

# The reason code a plain recovery carries: the lease expired, and another worker
# picked the run up from durable state. Named here so the plan's code and the
# closed vocabulary cannot drift.
RECOVERY_RESUMED: Final[OnboardingReasonCode] = "lease_expired_recovered"

# The three session outcomes of a recovery, in the order recovery prefers them.
SESSION_REATTACHED: Final[OnboardingReasonCode] = "session_reattached"
SESSION_RECREATED: Final[OnboardingReasonCode] = "session_recreated"
SESSION_UNREATTACHABLE: Final[OnboardingReasonCode] = "session_unreattachable"

# The phase a recovery that cannot proceed parks the run at. ``paused`` is the
# recoverable configuration state of the design's status table: an operator can
# act on it and the run can be resumed, which is what Requirement 15.9 asks for
# and what makes "never marked failed" true.
RECOVERY_PAUSE_PHASE: Final[OnboardingPhase] = "paused"

# Why a recovery pauses. Two reasons only: the ledger cannot say whether a
# submission reached the provider, or the run's authenticated session is gone.
RECOVERY_PAUSE_REASONS: Final[frozenset[OnboardingReasonCode]] = frozenset(
    {OUTCOME_UNKNOWN, SESSION_UNREATTACHABLE}
)

# Why a recovery continues. A continuing plan says how the session was obtained,
# or says the phase bears no session at all.
RECOVERY_CONTINUE_REASONS: Final[frozenset[OnboardingReasonCode]] = frozenset(
    {RECOVERY_RESUMED, SESSION_REATTACHED, SESSION_RECREATED}
)

# What made this recovery necessary, and the continuity event the reattach is
# recorded under. Both members are also members of
# ``browser_service.session_manager.SESSION_CONTINUITY_EVENTS`` — the set of
# events that must *not* end a bound session. The alignment is asserted in this
# feature's tests rather than at import here, because ``ops`` deliberately does
# not import the browser service.
RecoveryTrigger = Literal["worker_restart", "api_restart"]
RECOVERY_TRIGGERS: Final[tuple[RecoveryTrigger, ...]] = get_args(RecoveryTrigger)

# The restart that Requirement 16.14 is about: the API process came back and every
# non-terminal run has to continue from durable state.
API_RESTART: Final[RecoveryTrigger] = "api_restart"

# Session-bearing phases that presuppose an *authenticated* session. A fresh
# session in one of these is anonymous, so re-entering the phase from its start
# would drive a logged-out page rather than recover the run (Requirement 15.9).
# The pre-authentication phases are absent on purpose: login, signup, and
# verification are exactly the phases whose job is to establish authentication, so
# a new session there is a legitimate restart of the phase.
AUTHENTICATED_SESSION_PHASES: Final[frozenset[OnboardingPhase]] = frozenset(
    {"authenticated", "developer_app", "credential_generation"}
)

# What a recovery concluded.
#   ``continue``          -> drive ``plan.phase``; the session, if any, is named.
#   ``pause``             -> commit ``paused`` with ``plan.reason_code`` and stop.
#   ``restart_research``  -> the run has no profile to be attributable to, so the
#                            walk begins again at ``research``; nothing is reused.
#   ``terminal``          -> the run already finished. Recovery reports it so a
#                            restart sweep can skip it (Requirement 16.14).
RecoveryDisposition = Literal["continue", "pause", "restart_research", "terminal"]
RECOVERY_DISPOSITIONS: Final[tuple[RecoveryDisposition, ...]] = get_args(RecoveryDisposition)

# Import-time proof of the four claims this section's constants make. A pause
# target the phase table refuses would surface as a raised transition while a
# crashed run was being recovered; an authenticated-session phase that is not
# session-bearing would mean the reattach path never runs for it.
assert AUTHENTICATED_SESSION_PHASES <= SESSION_BEARING_PHASES, (
    "a phase that needs an authenticated session must be session-bearing"
)
assert all(
    is_legal_phase_transition(phase, RECOVERY_PAUSE_PHASE) for phase in AUTHENTICATED_SESSION_PHASES
), "every phase a recovery may park must admit the pause boundary"
assert RECOVERY_PAUSE_PHASE not in TERMINAL_PHASES, (
    "the recovery pause must be a recoverable state, never a terminal one"
)
assert (RECOVERY_PAUSE_REASONS | RECOVERY_CONTINUE_REASONS) <= frozenset(ONBOARDING_REASON_CODES), (
    "every recovery reason code must be a member of the closed onboarding vocabulary"
)


class BoundSessionReattacher(Protocol):
    """How recovery asks for the run's bound session, and only then for a new one.

    Two verbs, in the order recovery uses them, and neither of them can end a
    session: there is no release verb here, so a recovery cannot cost a run the
    authentication it is trying to preserve (Requirement 15.3). The release verbs
    live on :class:`ReleasableSession` and on the run-control surface, which are
    the paths allowed to use them.

    A ``SessionManager``-backed adapter satisfies this by looking the run's bound
    sessions up and calling ``retain(session_id, event=event)`` for the reattach,
    and ``create(...)`` for the second verb. Both return a session id rather than a
    session object because a plan is inert: recovery reports which session the next
    phase should be driven on, and the driver's own
    :class:`LoopSessionFactory` is what opens it.
    """

    async def reattach_bound_session(
        self, *, run_id: str, app_slug: str, event: RecoveryTrigger
    ) -> str | None:
        """The id of the run's still-live bound session, or ``None``.

        POST: the returned id is unchanged from the one the run was already bound
              to (Requirement 15.4), and the session is recorded as retained under
              ``event`` so the restart does not look like idleness. ``None`` means
              no bound session could be reattached, and nothing was created.
        """

    async def create_session(
        self, *, run_id: str, app_slug: str, allowed: BrowserAllowedHosts
    ) -> str | None:
        """Create exactly one session bound to the run, confined to ``allowed``.

        POST: at most one session is created per call (Requirement 15.5), bound to
              the run and the app slug and confined to the run's committed
              allow-list. ``None`` means none could be created, which recovery
              treats the same way it treats an unreattachable session rather than
              as a driveable phase.
        """


class RecoveryEffectReader(Protocol):
    """The one read recovery needs over the effect reservations of a run.

    Deliberately a single read verb. The settlement verbs
    (``complete_effect_reservation``, ``mark_effect_reservation_outcome_unknown``)
    exist on :class:`SQLitePhaseHistoryStore` and on
    :class:`ops.runs.resume.OnboardingEffectLedger`, and their absence here is what
    makes "recovery restricts itself to reads" checkable rather than reviewed
    (Requirement 16.11).
    """

    def reservations(self, *, run_id: str) -> tuple[EffectReservationRecord, ...]:
        """Every standing reservation for the run, in reservation order."""


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    """Where a crashed run stands, and what the next worker should do about it.

    Inert by construction: every field is a fact read from durable state or the id
    of a session that was reattached or created, and there is no verb here. The
    driver turns a ``continue`` plan into work by driving ``phase``; a ``pause``
    plan into the one boundary it names; and skips the run entirely on
    ``terminal``.

    ``reenter_phase_from_start`` is ``True`` exactly when the session had to be
    recreated: a fresh session is not standing where the old one stood, so the
    phase is re-entered from its start rather than continued mid-page
    (Requirement 15.5). ``profile_digest`` is the digest the run's last committed
    boundary recorded, carried through unchanged (Requirement 16.10).
    """

    run_id: str
    disposition: RecoveryDisposition
    phase: OnboardingPhase
    attempt: int
    profile_digest: str
    reason_code: OnboardingReasonCode
    session_id: str | None = None
    reenter_phase_from_start: bool = False
    effects: tuple[EffectPlan, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.run_id, field="run id")
        _phase(self.phase)
        _attempt(self.attempt)
        _reason_code(self.reason_code)
        if self.disposition not in RECOVERY_DISPOSITIONS:
            raise ValueError("a recovery plan carries a declared recovery disposition")
        # Empty only for a run with no profile to be attributable to, which is the
        # one case that restarts research rather than resuming anything.
        if self.profile_digest:
            _profile_digest(self.profile_digest)
        elif self.disposition != "restart_research":
            raise ValueError("a resumed run carries the profile digest it recorded")
        if self.session_id is not None:
            _identifier(self.session_id, field="browser session id")
            if self.phase not in SESSION_BEARING_PHASES:
                raise ValueError("only a session-bearing phase carries a browser session")
        if self.reenter_phase_from_start != (self.reason_code == SESSION_RECREATED):
            raise ValueError("a phase is re-entered from its start exactly when a session was new")
        if self.disposition == "continue":
            if self.phase in TERMINAL_PHASES:
                raise ValueError("a terminal run is not continued")
            if self.reason_code not in RECOVERY_CONTINUE_REASONS:
                raise ValueError("a continuing recovery names how its session was obtained")
        elif self.disposition == "pause" and self.reason_code not in RECOVERY_PAUSE_REASONS:
            raise ValueError(
                "a recovery pauses on an ambiguous effect or an unreattachable session"
            )
        elif self.disposition == "terminal" and self.phase not in TERMINAL_PHASES:
            raise ValueError("a terminal recovery plan names a terminal phase")
        elif self.disposition == "restart_research" and self.phase != INITIAL_PHASE:
            raise ValueError("a restarted walk begins at the initial phase")

    @property
    def is_resumable(self) -> bool:
        """Whether the next worker should drive :attr:`phase` (Requirement 16.14)."""

        return self.disposition == "continue"

    @classmethod
    def restart_research(cls, run_id: str) -> RecoveryPlan:
        """The plan for a run with no committed profile: begin the walk again.

        Not a failure and not a pause: a run whose history carries no digest a
        profile can be loaded by has nothing to be attributable to, and research
        reserves no effect, so starting it again is safe. This is the only path on
        which a recovery leaves the recorded digest empty, and it is empty because
        there was none to carry.
        """

        return cls(
            run_id=run_id,
            disposition="restart_research",
            phase=INITIAL_PHASE,
            attempt=0,
            profile_digest="",
            reason_code=RECOVERY_RESUMED,
        )


async def recover_run(
    *,
    run_id: str,
    worker_id: str,
    deps: OnboardingDeps,
    sessions: BoundSessionReattacher | None = None,
    effects: RecoveryEffectReader | None = None,
    trigger: RecoveryTrigger = "worker_restart",
) -> RecoveryPlan:
    """Reconstruct enough state to resume a run another worker was driving.

    PRE:
      P1. the caller holds the run's lease — ``deps.leases.claim`` succeeded
          because the prior lease expired or was released. Recovery neither claims
          nor releases: it is called under a claim, and the release stays with
          :class:`LeaseGuard` so a run cannot be released twice (Requirement
          16.13).
      P2. ``trigger`` names why recovery is running, and is a member of
          :data:`RECOVERY_TRIGGERS`.

    POST:
      Q1. ``plan.phase`` is the last durably committed phase, never an earlier one
          (Requirement 12.10, Property 5), except where that phase is one no
          worker may stand in, which :func:`resumption_phase` recomputes from the
          prior durable phase.
      Q2. in a session-bearing phase, a reattach is attempted before anything is
          created. A reattached session keeps its id and the plan carries
          ``session_reattached``; a created one carries ``session_recreated`` and
          asks for the phase to be re-entered from its start; a phase that needs
          an authenticated session and got neither pauses with
          ``session_unreattachable`` (Requirements 15.2, 15.4, 15.5, 15.9).
      Q3. every standing reservation for the resumption phase is reported as an
          :class:`~ops.onboarding.effects.EffectPlan`, and a single
          ``pause_outcome_unknown`` among them pauses the run — recovery never
          resubmits on a guess (Property 6).
      Q4. no side effect is performed and no phase is committed: the phase port is
          read through ``history`` and the effect port has one read verb
          (Requirement 16.11). The one thing recovery may create is a browser
          session, and only when the run is going to continue without one.
      Q5. a terminal run is reported as ``terminal`` and is never driven, so an
          API-restart sweep continues exactly the non-terminal runs
          (Requirement 16.14).

    INVARIANTS:
      I1. the profile is loaded by the digest the run recorded, so the allow-list
          that authorized the actions before the crash is the one that authorizes
          the next; no research runs and the recorded digest is unchanged
          (Requirements 16.9, 16.10).
    """

    if trigger not in RECOVERY_TRIGGERS:
        raise ValueError("a recovery trigger is a worker restart or an api restart")
    _identifier(worker_id, field="worker id")
    # One read of durable state answers where the run stands and under which
    # profile, the same single read ``drive_run`` performs for the same reason.
    history = deps.phases.history(run_id=run_id)
    phase, attempt = resumption_phase(history)  # Q1
    profile = _load_profile(history=history, run_id=run_id, deps=deps)  # I1
    if profile is None:
        LOGGER.info("onboarding run %s recovered with no committed profile", run_id)
        return RecoveryPlan.restart_research(run_id)
    digest = history[-1].profile_digest if history else profile.profile_digest  # I1

    if phase in TERMINAL_PHASES:  # Q5
        return RecoveryPlan(
            run_id=run_id,
            disposition="terminal",
            phase=phase,
            attempt=attempt,
            profile_digest=digest,
            reason_code=history[-1].reason_code if history else RECOVERY_RESUMED,
        )

    planned = _recovery_effect_plans(run_id=run_id, phase=phase, effects=effects)  # Q3
    session_id: str | None = None
    reason: OnboardingReasonCode = RECOVERY_RESUMED
    if phase in SESSION_BEARING_PHASES:
        if sessions is None:
            # A wiring defect rather than a run outcome: a session-bearing phase
            # cannot be recovered without the port that reattaches its session, and
            # guessing "create one" would silently drop the run's authentication.
            raise PhaseNotDrivable(phase, "recovery has no bound-session reattacher wired")
        session_id = await sessions.reattach_bound_session(
            run_id=run_id, app_slug=profile.app_slug, event=trigger
        )
        if session_id is not None:  # Q2, Requirement 15.4
            reason = SESSION_REATTACHED

    unknown = tuple(plan for plan in planned if plan.disposition == "pause_outcome_unknown")
    if unknown:
        # Q3: the ledger already refuses to authorize a second submission for these
        # keys, so the run pauses with its session kept and nothing new created.
        LOGGER.info(
            "onboarding run %s recovered with %d effect(s) of unknown outcome in phase %s",
            run_id,
            len(unknown),
            phase,
        )
        return RecoveryPlan(
            run_id=run_id,
            disposition="pause",
            phase=phase,
            attempt=attempt,
            profile_digest=digest,
            reason_code=OUTCOME_UNKNOWN,
            # Set only by the reattach above, so a paused run reports the session it
            # kept and never one this path created.
            session_id=session_id,
            effects=planned,
        )

    if phase in SESSION_BEARING_PHASES and reason != SESSION_REATTACHED:
        assert sessions is not None  # refused above for a session-bearing phase
        if phase in AUTHENTICATED_SESSION_PHASES:
            # Requirement 15.9: a fresh session here is anonymous, so the run moves
            # to the recoverable configuration state instead of driving a
            # logged-out provider console.
            LOGGER.info(
                "onboarding run %s cannot reattach the session phase %s requires", run_id, phase
            )
            return RecoveryPlan(
                run_id=run_id,
                disposition="pause",
                phase=phase,
                attempt=attempt,
                profile_digest=digest,
                reason_code=SESSION_UNREATTACHABLE,
                effects=planned,
            )
        session_id = await sessions.create_session(
            run_id=run_id, app_slug=profile.app_slug, allowed=profile.allowed_hosts()
        )
        if session_id is None:
            # Nothing to drive the phase on. Reported as the same recoverable state
            # rather than as a phase with an implicit session.
            return RecoveryPlan(
                run_id=run_id,
                disposition="pause",
                phase=phase,
                attempt=attempt,
                profile_digest=digest,
                reason_code=SESSION_UNREATTACHABLE,
                effects=planned,
            )
        reason = SESSION_RECREATED  # Requirement 15.5

    LOGGER.info(
        "onboarding run %s recovered at phase %s on %s (%s) after a %s",
        run_id,
        phase,
        session_id or "no session",
        reason,
        trigger,
    )
    return RecoveryPlan(
        run_id=run_id,
        disposition="continue",
        phase=phase,
        attempt=attempt,
        profile_digest=digest,
        reason_code=reason,
        session_id=session_id,
        reenter_phase_from_start=reason == SESSION_RECREATED,
        effects=planned,
    )


async def recover_runs(
    *,
    run_ids: Sequence[str],
    worker_id: str,
    deps: OnboardingDeps,
    sessions: BoundSessionReattacher | None = None,
    effects: RecoveryEffectReader | None = None,
    trigger: RecoveryTrigger = API_RESTART,
) -> tuple[RecoveryPlan, ...]:
    """Plan recovery for a set of runs, which is what a restart sweep needs.

    PRE:  every id in ``run_ids`` is a run whose lease the caller holds.
    POST: one plan per run, in the order asked for. Terminal runs are reported as
          ``terminal`` rather than omitted, so the caller can tell "already
          finished" from "not asked about", and the non-terminal ones carry the
          phase they continue from (Requirement 16.14). Nothing is committed.
    """

    return tuple(
        [
            await recover_run(
                run_id=run_id,
                worker_id=worker_id,
                deps=deps,
                sessions=sessions,
                effects=effects,
                trigger=trigger,
            )
            for run_id in run_ids
        ]
    )


def _recovery_effect_plans(
    *, run_id: str, phase: OnboardingPhase, effects: RecoveryEffectReader | None
) -> tuple[EffectPlan, ...]:
    """The standing disposition of every reservation the resumption phase owns.

    Read rather than re-derived, and that is the point: deriving the operation keys
    again would need the profile inputs that produced them, while the reservation
    rows already carry the *standing* answer for each key — what a worker arriving
    now is authorized to do about it. Nothing here reserves anything, so recovery
    cannot turn a key it merely looked at into a submission it may perform
    (Requirement 16.11).

    An unwired reader yields no plans, which is the honest answer for a deployment
    whose recovery path has no effect view: the driver then reserves through
    ``commit_phase_with_reservation`` as it always does, and the ledger's
    uniqueness — not this function — is what stops a second submission.
    """

    if effects is None:
        return ()
    return tuple(
        EffectPlan(
            operation_key=record.operation_key,
            provider=EFFECT_PROVIDER,
            action=record.effect,
            disposition=record.disposition,
            receipt=dict(record.receipt) if record.receipt else None,
            reason_code=record.reason_code,
        )
        for record in effects.reservations(run_id=run_id)
        if record.phase == phase
    )


async def _drive_phase(
    *,
    run_id: str,
    phase: OnboardingPhase,
    profile: ProviderProfile | None,
    lease: Lease,
    deps: OnboardingDeps,
    tally: _RunTally,
) -> PhaseStep:
    """Drive one phase once: a registered handler, the mailbox, or the loop.

    Dispatch order is the design's: a registered handler wins, because a phase with
    provider-visible ordering owns itself; ``email_verification`` is then the one
    phase driven by a service rather than a page walk, since the step that makes it
    progress happens in a mailbox; everything else is the bounded action loop.
    """

    handler = deps.handlers.get(phase)
    if handler is not None:
        return await handler(run_id=run_id, phase=phase, profile=profile, lease=lease, deps=deps)
    if phase == VERIFICATION_PHASE and _verification_is_wired(deps):
        if profile is None:
            raise PhaseNotDrivable(phase, "the run has no committed provider profile")
        return await _drive_verification(
            run_id=run_id, profile=profile, lease=lease, deps=deps, tally=tally
        )
    if phase not in PHASE_SUCCESSORS:
        raise PhaseNotDrivable(phase, "no handler is registered and no loop goal is declared")
    if profile is None:
        # The allow-list that confines the browser is a projection of the
        # profile, so a browser phase without one cannot be driven at all.
        raise PhaseNotDrivable(phase, "the run has no committed provider profile")

    goal = deps.goals.goal_for(phase=phase, profile=profile)
    session = await deps.sessions.session_for(run_id=run_id, phase=phase, lease=lease)
    try:
        result = await run_action_loop(
            phase=phase,
            goal=goal,
            session=session,
            allowed=profile.allowed_hosts(),
            budget=deps.budget,
            decider=deps.decider,
            telemetry=deps.telemetry,
            deadlines=deps.deadlines,
        )
    except DecisionFailed as failure:
        # The chain was called and could not answer usably: pause naming which of
        # the causes it was rather than letting the phase look slow (R4.5, R4.6).
        return step_for_decision_failure(failure)
    tally.record(result)
    # The one mid-flight operator prompt is taken through the pause path, which
    # records where it paused and counts it before the driver commits the boundary.
    # The loop session is passed as the pause port, which carries no verb that
    # could release the session it is holding open (Requirement 11.4).
    return await step_for_loop_outcome(
        run_id=run_id, phase=phase, result=result, session=session, deps=deps
    )


def _verification_is_wired(deps: OnboardingDeps) -> bool:
    """Whether the mailbox path can drive ``email_verification`` at all.

    All three of the binding, the vault, and the mailbox adapter are needed: with
    any of them missing there is either no run-bound query to ask, nowhere to stage
    a one-time code, or nothing to ask. A partially wired deployment falls back to
    the loop rather than pretending to read a mailbox.
    """

    return (
        deps.verification_binding is not None
        and deps.vault is not None
        and deps.verification is not None
    )


async def _drive_verification(
    *,
    run_id: str,
    profile: ProviderProfile,
    lease: Lease,
    deps: OnboardingDeps,
    tally: _RunTally,
) -> PhaseStep:
    """Drive ``email_verification`` through the mailbox service (LL-3.4).

    The attempt number comes from the durable ladder rather than from this walk:
    every unresolved attempt ends the worker's turn with a deferral, so a count held
    here would restart at zero on the next claim and poll forever (Requirement
    7.28). Counting it here — before the search — is also what makes an attempt that
    crashes mid-flight cost a rung rather than nothing.
    """

    binding = deps.verification_binding
    vault = deps.vault
    assert binding is not None and vault is not None  # _verification_is_wired
    challenge_ms = _verification_challenge_ms(run_id=run_id, deps=deps)
    consumed = max(deps.phases.next_verification_attempt(run_id=run_id) - 1, 0)
    tally.verification_attempts = consumed + 1
    context = binding.verification_context(run_id=run_id, challenge_issued_at_ms=challenge_ms)
    session = await binding.verification_session(run_id=run_id, lease=lease)
    return await await_verification(
        run_id=run_id,
        profile=profile,
        provider=deps.verification,
        session=session,
        vault=vault,
        context=context,
        attempt=consumed,
        budget=deps.verification_budget or VerificationBudget(),
        clock=deps.clock,
    )


def _verification_challenge_ms(*, run_id: str, deps: OnboardingDeps) -> int:
    """When this run's verification challenge became durable, in epoch ms.

    Read from the committed boundary into ``email_verification`` rather than from
    the clock, so every attempt — including one made by a later worker — measures
    freshness against the same floor and the floor never moves backwards
    (invariant I1 of the verification service).
    """

    for boundary in reversed(deps.phases.history(run_id=run_id)):
        if boundary.to_phase == VERIFICATION_PHASE:
            return _epoch_ms(boundary.committed_at)
    raise PhaseNotDrivable(
        VERIFICATION_PHASE, "no committed boundary issued this run's verification challenge"
    )


def _epoch_ms(moment: str) -> int:
    """One stored timestamp as epoch milliseconds.

    The stored form is the one :func:`_moment` writes — an aware ISO instant with a
    ``Z`` suffix — so a value that does not parse is a corrupted row rather than a
    freshness floor to guess at.
    """

    try:
        parsed = datetime.fromisoformat(moment.replace("Z", "+00:00"))
    except ValueError:
        raise PhaseNotDrivable(
            VERIFICATION_PHASE, "the verification boundary carries an unreadable timestamp"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


def _load_profile(
    *, history: Sequence[PhaseTransition], run_id: str, deps: OnboardingDeps
) -> ProviderProfile | None:
    """The profile the run's phase history recorded, by digest (I2).

    The digest is read from the last committed boundary rather than from the
    run-to-profile binding, so the profile loaded here is the one that authorized
    the phase being resumed. The binding is the fallback for a run whose history
    is still empty.
    """

    if history:
        profile = deps.profiles.get(profile_digest=history[-1].profile_digest)
        if profile is not None:
            return profile
    return deps.profiles.get_for_run(run_id=run_id)


def _moment(value: datetime) -> str:
    """One aware instant as the timestamp text the durable rows carry."""

    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _port_conformance(store: SQLitePhaseHistoryStore) -> PhaseHistoryStore:
    """Typecheck-only proof that the SQLite store satisfies the port.

    The composition root binds them together in ``ops.onboarding.composition``;
    this keeps a renamed or re-signatured method from going unnoticed until then.
    """

    return store


def _recovery_effect_reader_conformance(store: SQLitePhaseHistoryStore) -> RecoveryEffectReader:
    """Typecheck-only proof that the same store satisfies the reservation reader."""

    return store


__all__ = [
    "ADMISSION_PROMPT_COUNTER",
    "ADMISSION_PROMPT_PHASE",
    "API_RESTART",
    "AUTHENTICATED_SESSION_PHASES",
    "AUTONOMOUS_LEGAL_AUTHORITIES",
    "AUTONOMY_VERDICTS",
    "BLOCKING_APPROVAL_REQUIREMENTS",
    "BLOCKING_BILLING_REQUIREMENTS",
    "CAPTCHA_BUDGET_EXHAUSTED",
    "CAPTCHA_CANCELLED",
    "CAPTCHA_DETECTED",
    "CAPTCHA_INTERRUPTIBLE_PHASES",
    "CAPTCHA_PAUSE_PHASE",
    "CAPTCHA_PROMPT_COUNTER",
    "CAPTCHA_RESOLVED",
    "CAPTCHA_RESUME_SIGNALS",
    "CREDENTIAL_FLOW_KINDS",
    "DEFAULT_CAPTCHA_BUDGET",
    "DEVELOPER_APP_APPROVAL_REQUIRED",
    "DEVELOPER_APP_BILLING_REQUIRED",
    "DEVELOPER_APP_CREATED",
    "DEVELOPER_APP_EFFECT",
    "DEVELOPER_APP_FLOW_UNSUPPORTED",
    "DEVELOPER_APP_NAME_PREFIX",
    "DEVELOPER_APP_NAME_REF",
    "DEVELOPER_APP_PHASE",
    "DEVELOPER_APP_PROFILE_UNAVAILABLE",
    "DEVELOPER_APP_RECEIPT_FLOW_KEY",
    "DEVELOPER_APP_RECEIPT_KEY",
    "DUPLICATE_ACCOUNT_REROUTE",
    "DUPLICATE_ACCOUNT_REROUTE_SOURCE",
    "DUPLICATE_ACCOUNT_REROUTE_TARGET",
    "EFFECT_BEARING_PHASES",
    "EFFECT_ROW_STATUSES",
    "GENERATION_COUNTERS",
    "LEGAL_ACCEPTANCE_EVIDENCE",
    "LEGAL_ACCEPTANCE_GATE",
    "LEGAL_DOCUMENT_DIGEST_LENGTH",
    "MAX_CAPTCHA_PAUSES",
    "MAX_CORRELATION_ID_LENGTH",
    "MAX_RENEWAL_FAILURES",
    "MIDFLIGHT_OPERATOR_PROMPTS",
    "NO_STEP_TAKEN",
    "OUTCOME_UNKNOWN",
    "PHASE_REPLAY_NOOP",
    "PHASE_SUCCESSORS",
    "PROFILE_DIGEST_LENGTH",
    "RECOVERY_CONTINUE_REASONS",
    "RECOVERY_DISPOSITIONS",
    "RECOVERY_PAUSE_PHASE",
    "RECOVERY_PAUSE_REASONS",
    "RECOVERY_RESUMED",
    "RECOVERY_TRIGGERS",
    "SESSION_REATTACHED",
    "SESSION_RECREATED",
    "SESSION_UNREATTACHABLE",
    "SUBMITTED_STATUSES",
    "VERIFICATION_ACCEPTED",
    "VERIFICATION_BACKOFF_CAP_SECONDS",
    "VERIFICATION_CLAIM_CONTENDED",
    "VERIFICATION_CODE_KIND",
    "VERIFICATION_CODE_TTL_SECONDS",
    "VERIFICATION_COUNTER",
    "VERIFICATION_JITTER_MAX",
    "VERIFICATION_JITTER_MIN",
    "VERIFICATION_LINK_BLOCKED",
    "VERIFICATION_PHASE",
    "VERIFICATION_PURPOSE",
    "VERIFICATION_UNRESOLVED",
    "WAITING_PHASES",
    "AcceptedDocument",
    "AdmissionPromptStore",
    "AuditTrailLegalEvidence",
    "AutonomyOutcome",
    "AutonomyOutcomeReader",
    "AutonomyOutcomeStore",
    "AutonomyVerdict",
    "BoundSessionReattacher",
    "CaptchaBudget",
    "CaptchaPause",
    "CaptchaPauseStore",
    "CaptchaResumeSignal",
    "DeveloperAppBinding",
    "DeveloperAppFlows",
    "DeveloperAppPhaseHandler",
    "DeveloperAppRequest",
    "EffectReservationRecord",
    "LeaseGuard",
    "LeaseGuardStatus",
    "LedgerAutonomyOutcomes",
    "LegalAcceptance",
    "LegalEvidenceStore",
    "LoginReferenceBinder",
    "LoopSessionFactory",
    "OnboardingDeps",
    "OperatorPrompts",
    "PausedSession",
    "PhaseGoalFactory",
    "PhaseHandler",
    "PhaseHistoryStore",
    "PhaseNotDrivable",
    "PhaseStep",
    "PhaseStepKind",
    "PhaseTransition",
    "RecoveryDisposition",
    "RecoveryEffectReader",
    "RecoveryPlan",
    "RecoveryTrigger",
    "ReleasableSession",
    "RenewalCheck",
    "RunPlanner",
    "RunPlanningPorts",
    "RunPlanValidator",
    "ReservedPhaseCommit",
    "SQLitePhaseHistoryStore",
    "VerificationBinding",
    "VerificationBudget",
    "VerificationContext",
    "VerificationSecretVault",
    "VerificationSession",
    "accept_legal_terms",
    "adopt_signup_references_for_login",
    "autonomy_verdict",
    "await_verification",
    "developer_app_flows",
    "developer_app_gate",
    "developer_app_goal",
    "developer_app_name",
    "drive_developer_app",
    "drive_run",
    "emit_admission_prompt",
    "is_duplicate_account_reroute",
    "midflight_gate_disposition",
    "midflight_prompt_count",
    "operator_prompts",
    "pause_for_captcha",
    "has_entered_a_session",
    "phase_correlation_id",
    "plan_admission",
    "recover_run",
    "recover_runs",
    "resume_from_captcha",
    "resumption_phase",
    "step_for_decision_failure",
    "step_for_loop_outcome",
    "step_for_loop_result",
    "verification_backoff_seconds",
    "verification_query",
]
