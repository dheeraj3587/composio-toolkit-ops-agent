"""Recovery of runs left holding a browser with nothing driving them.

Two sweeps live here and they are deliberately paired. The startup sweep recovers
runs stranded by the previous shutdown; the periodic sweep recovers runs that
landed at ``browser_running`` without a live operation. Both end at the same
recoverable ``configuration_required`` state and both release the browser session,
so keeping them together makes it obvious they must stay consistent.

Both are best effort and must never crash boot or a sweep: a reconciliation error
is logged and skipped, because failing to recover a run is recoverable while
failing to start the service is not.

The second half of this module is the operator's *recovery* half of the onboarding
run-control surface: Reset and Retry Current Step. Pause, Resume, and Cancel stop a
run (:mod:`ops.runs.resume`); these two put one back to work, which is why they sit
next to the sweeps that do the same thing without an operator. Four properties
shape them:

Reset preserves the vault, structurally rather than by restraint.
    Reset's only view of the vault is the reference-only probe
    (:class:`ops.onboarding.admission.CredentialReferenceProbe`), whose one method
    returns ``vault://`` references and selects no ciphertext column at all. There
    is no delete call anywhere on this path, so "no row in ``secret_vault.db`` is
    touched" (Requirements 14.9, 14.10, Property 13) follows from the shape of the
    dependency and not from a reviewer checking every branch. Preserving the
    credentials is what makes the restarted run take the login route with reason
    code ``credentials_present`` instead of creating a second account.

Retry reads the generation counter; it never advances it.
    Requirement 14.15 is the whole reason retry exists as its own method:
    ``current_generation`` returns the value the failed attempt used, so the retry
    derives the operation key that is *already reserved*, finds the reservation,
    and skips a completed effect instead of minting a second credential. Only the
    credential supersede path calls ``next_generation``, and it is not reachable
    from here.

Reset reaches ``research`` through the phase table, or not at all.
    The table declares ``paused -> research`` and nothing else into ``research``,
    so a reset of a running phase parks the run first (``phase -> paused ->
    research``) and a reset of a phase with neither edge — ``vault_check`` is the
    one — is refused with nothing written and no session released. That is a real
    gap against Requirement 14.8, and it is reported here rather than papered over
    by widening the table from a control surface.

The coarse status may lag the phase, deliberately.
    ``researching`` is reachable from ``configuration_required`` and ``failed``
    but not from ``waiting_for_hitl``, which is where a parked run sits. The
    shared projection keeps the status and still records the phase: the phase is
    the value the next worker resumes from, and hiding a committed boundary
    because its status edge was refused would be the worse failure.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal, Protocol, cast

from ops.browser.link_log import log_event

# The backend contract, not a concrete backend: with Browser Use removed the
# only implementation is the Playwright harness, and these call sites only ever
# needed the protocol. Aliased so the annotations below read unchanged.
from ops.browser.provider import BrowserProvider as BrowserWorker
from ops.core.config import Settings
from ops.core.state import BrowserProvider, RunStatus, validate_status_transition
from ops.core.storage import OperationsStorage
from ops.onboarding.admission import CredentialReferenceProbe, probe_login_refs
from ops.onboarding.driver import (
    OUTCOME_UNKNOWN,
    PHASE_REPLAY_NOOP,
    WAITING_PHASES,
    PhaseHistoryStore,
    PhaseTransition,
)
from ops.onboarding.effects import EffectDisposition, OnboardingEffect
from ops.onboarding.phase import (
    INITIAL_PHASE,
    TERMINAL_PHASES,
    OnboardingPhase,
    OnboardingReasonCode,
    is_legal_phase_transition,
)
from ops.runs.projections import _parse_timestamp
from ops.runs.resume import (
    PAUSED_PHASE,
    BrowserSessionRelease,
    EffectOutcomeProbe,
    OnboardingEffectLedger,
    OnboardingRunControlService,
)

LOGGER = logging.getLogger("composio_ops.run_service")


class RunReconciliationContext(Protocol):
    """The run-service state and browser teardown hooks these sweeps need."""

    storage: OperationsStorage
    _settings: Settings | None

    def _browser_worker_for(self, record: Mapping[str, Any]) -> BrowserWorker | None: ...

    def _session_context_for(self, run_id: str) -> Any: ...

    def _release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None: ...

    def _run_lock(self, run_id: str) -> Any: ...

    def _continue_pristine_playwright_run(
        self,
        record: Mapping[str, Any],
    ) -> dict[str, Any] | None: ...


class RunReconciliationService:
    """Move unrecoverable browser runs to a recoverable state and free the slot."""

    def __init__(self, context: RunReconciliationContext) -> None:
        self._context = context

    @property
    def storage(self) -> OperationsStorage:
        return self._context.storage

    def reconcile_stranded_runs(self) -> None:
        """Recover runs stranded by the previous shutdown.

        A run left at ``browser_running`` cannot progress after an api restart
        because its in-process navigation thread is gone; move it to the
        recoverable ``configuration_required`` state so the operator can retry
        instead of watching it spin forever. ``waiting_for_hitl`` runs are left
        intact: the provider session id is now persisted, so they can be resumed.
        Best-effort and never fatal to startup.
        """

        # Provider capability decides which statuses are recoverable. The in-process
        # Playwright browser dies with the API process, so BOTH browser_running and
        # waiting_for_hitl must be reconciled — claiming such a run is resumable
        # would be false.
        #
        # The browser SERVICE is the other case: Chromium is in its own container, so
        # a session can genuinely outlive an API restart. But the capability flag
        # alone is not evidence, so each waiting_for_hitl run is CHECKED against the
        # service (see _browser_session_is_live); only a session the service still
        # reports ACTIVE is left resumable.
        try:
            offset = 0
            while True:
                batch = self.storage.list_runs(limit=100, offset=offset)
                if not batch:
                    break
                for record in batch:
                    status = record.get("status")
                    run_id = str(record.get("run_id") or "")
                    if (
                        status == "route_selected"
                        and record.get("state_engine") == "canonical_v1"
                        and record.get("execution_mode") == "operations"
                        and record.get("route_kind") == "playwright"
                        and record.get("browser_provider") == "playwright"
                        and record.get("phase")
                        in {
                            "browser_pending",
                            "browser_starting",
                            "authentication_submitted",
                        }
                    ):
                        self.recover_pristine_browser_pending(record)
                        continue
                    worker = self._context._browser_worker_for(record)
                    if worker is None and status in {"browser_running", "waiting_for_hitl"}:
                        # A disabled/unconfigured provider cannot own a live session.
                        # Preserve the run and its audit history, but stop presenting
                        # a dead viewer as resumable.
                        self.reconcile_one_stranded(
                            run_id,
                            stranded_statuses=("browser_running", "waiting_for_hitl"),
                            reason="provider_unavailable_session_lost",
                        )
                        continue
                    reattach = bool(getattr(worker, "supports_restart_reattach", True))
                    stranded_statuses = (
                        ("browser_running",)
                        if reattach
                        else ("browser_running", "waiting_for_hitl")
                    )
                    reason = (
                        "api_restart_stranded_browser_run"
                        if reattach
                        else "playwright_session_lost_on_restart"
                    )
                    verifies_sessions = callable(getattr(worker, "reconcile_session", None))
                    if status in stranded_statuses:
                        self.reconcile_one_stranded(
                            run_id,
                            stranded_statuses=stranded_statuses,
                            reason=reason,
                        )
                    elif (
                        verifies_sessions
                        and status == "waiting_for_hitl"
                        and self.browser_session_is_live(record) is False
                    ):
                        # The service says this session is gone: the run cannot be
                        # resumed, so surface that instead of waiting forever on a
                        # browser that no longer exists.
                        self.reconcile_one_stranded(
                            run_id,
                            stranded_statuses=("waiting_for_hitl",),
                            reason="browser_service_session_lost",
                        )
                if len(batch) < 100:
                    break
                offset += 100
        except Exception:  # pragma: no cover - reconciliation must never crash boot
            LOGGER.warning("startup run reconciliation was skipped after an error")

    def recover_pristine_browser_pending(self, record: Mapping[str, Any]) -> None:
        """Continue only a browser dispatch whose side-effect boundary is pristine.

        The canonical runtime rechecks ``attempt``, effect identity, and the
        side-effect ledger under the per-run lock. A truly pristine run starts;
        evidence of a prior reservation is moved to effect reconciliation and can
        never be duplicated automatically.
        """

        run_id = str(record.get("run_id") or "")
        if not run_id:
            return
        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            return
        try:
            current = self.storage.get_run(run_id)
            if (
                current is None
                or current.get("status") != "route_selected"
                or current.get("state_engine") != "canonical_v1"
                or current.get("execution_mode") != "operations"
                or current.get("route_kind") != "playwright"
                or current.get("browser_provider") != "playwright"
            ):
                return
            self._context._continue_pristine_playwright_run(current)
        except Exception:  # pragma: no cover - one bad run must not abort the sweep
            LOGGER.warning("could not recover a pristine browser-pending run")
        finally:
            lock.release()

    def browser_session_is_live(self, record: Mapping[str, Any]) -> bool | None:
        """Ask the browser service whether a persisted session id still exists.

        Returns ``True`` when the service reports the session ACTIVE, ``False``
        when it is definitively gone, and ``None`` when the answer is unknown
        (service unreachable, or the provider cannot be queried). ``None`` must be
        treated as "leave the run alone": tearing a run down because the service
        was briefly unreachable would destroy a session that is actually alive.
        """

        worker = self._context._browser_worker_for(record)
        reconcile = getattr(worker, "reconcile_session", None)
        if not callable(reconcile):
            return None
        session_id = record.get("browser_session_id")
        if not isinstance(session_id, str) or not session_id:
            return False
        try:
            scope_kwargs = (
                {"capability_scope": str(record.get("run_id") or "")}
                if bool(getattr(worker, "requires_session_capability_scope", False))
                else {}
            )
            outcome = asyncio.run(reconcile(session_id, **scope_kwargs))
        except Exception:
            return None
        if outcome == "resumable":
            return True
        if outcome == "session_lost":
            return False
        # "unreachable" (or anything unexpected) is inconclusive, never a teardown.
        return None

    def reconcile_one_stranded(
        self,
        run_id: str,
        *,
        stranded_statuses: tuple[str, ...] = ("browser_running",),
        reason: str = "api_restart_stranded_browser_run",
    ) -> None:
        if not run_id:
            return
        release_provider: BrowserProvider | None = None
        try:
            with self.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if current is None or current.get("status") not in stranded_statuses:
                    return
                release_provider = cast(
                    BrowserProvider, current.get("browser_provider", "playwright")
                )
                previous_status = cast(RunStatus, current["status"])
                revision = int(current.get("state_revision", 0) or 0) + 1
                validate_status_transition(previous_status, "configuration_required", "reconcile")
                transaction.update_run(
                    run_id,
                    status="configuration_required",
                    phase="session_lost",
                    reason_code=reason,
                    state_revision=revision,
                    last_projected_revision=revision,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="run_reconciled_on_startup",
                    payload={
                        "previous_status": previous_status,
                        "status": "configuration_required",
                        "reason_code": reason,
                        "phase": "session_lost",
                        "external_actions": False,
                    },
                )
            if release_provider is not None:
                self._context._release_browser_session(
                    self._context._session_context_for(run_id),
                    release_provider,
                    reason=f"reconcile_{reason}",
                )
        except Exception:  # pragma: no cover - per-run best effort
            LOGGER.warning("could not reconcile a stranded run on startup")

    def reconcile_idle_browser_runs(self, *, limit: int = 100) -> int:
        """Recover runs stuck at ``browser_running`` with nothing driving them.

        A ``browser_running`` run is normally short-lived: either the navigation
        completes, or it stops at a human gate. Nothing sweeps this status, so a run
        whose projection landed here without a live operation used to sit forever and
        keep holding a browser slot — fatal where capacity is one session.

        This is the periodic counterpart to :meth:`reconcile_stranded_runs`, which
        only runs at startup. A run is touched ONLY when it has been idle far longer
        than any legitimate browser operation could take, so an in-flight navigation
        is never torn down: the threshold is derived from the provider operation
        timeout with a wide safety factor. The outcome is the same recoverable
        ``configuration_required`` state the startup path already produces, and the
        browser session is released.
        """

        settings = self._context._settings or Settings.from_env()
        # Derived from the longest single browser operation the client will wait on,
        # with a wide safety factor. This used to read the retired Browser Use task
        # timeout, which no longer exists — so the getattr fell through to its
        # default and the threshold no longer tracked the timeout it claimed to.
        idle_seconds = max(600, int(settings.browser_service_client_timeout_seconds) * 4)
        cutoff = datetime.now(UTC) - timedelta(seconds=idle_seconds)
        reconciled = 0
        for record in self.storage.list_runs(limit=limit, offset=0):
            if record.get("status") != "browser_running":
                continue
            run_id = str(record.get("run_id") or "")
            if not run_id:
                continue
            updated_at = _parse_timestamp(record.get("updated_at"))
            if updated_at is None or updated_at > cutoff:
                continue
            before = self.storage.get_run(run_id)
            self.reconcile_one_stranded(
                run_id,
                stranded_statuses=("browser_running",),
                reason="idle_browser_run_reconciled",
            )
            after = self.storage.get_run(run_id)
            if (
                isinstance(before, Mapping)
                and isinstance(after, Mapping)
                and before.get("status") != after.get("status")
            ):
                reconciled += 1
                log_event(
                    "browser.idle_run.reconciled",
                    run_id=run_id,
                    app_slug=record.get("app_slug"),
                    idle_seconds=idle_seconds,
                )
        return reconciled


# --- operator recovery controls over the onboarding phase machine -----------

# The closed-vocabulary reason code each recovery control writes onto the boundary
# it commits, and the audit event type that carries it. Both codes and both event
# types are the ones design LL-6.3 and the timeline table already name, so nothing
# here needs translating on its way to an API response.
RESET_REASON_CODE: Final[OnboardingReasonCode] = "run_reset"
RETRY_REASON_CODE: Final[OnboardingReasonCode] = "step_retried"
RESET_EVENT: Final = "onboarding_run_reset"
RETRIED_EVENT: Final = "onboarding_step_retried"

# The release reason a reset hands to the session port. A member of
# ``browser_service.session_manager.RUN_RELEASE_REASONS``, which is a closed
# enumeration: a reason outside it is refused by the service, so reset must name
# the reset reason exactly rather than decorating it.
RESET_RELEASE_REASON: Final = "run_reset"

# The reservation disposition that means "the provider already saw this one".
# ``skip`` is what the ledger records for a ``completed`` row, so these are the
# effects a retry must not re-submit (Requirement 14.13).
COMPLETED_DISPOSITION: Final[EffectDisposition] = "skip"

# The disposition that refuses a retry outright. An ambiguous outcome authorizes
# nothing, so re-attempting the step would be the blind resubmission the effect
# ledger exists to prevent (Requirement 13.10, Property 6).
UNKNOWN_DISPOSITION: Final[EffectDisposition] = "pause_outcome_unknown"

# The one effect whose operation key reads a durable generation counter (the sole
# key of ``ops.onboarding.driver.GENERATION_COUNTERS``). Retry reads that counter
# and never advances it, which is what makes it derive the already-reserved key.
CREDENTIAL_EFFECT: Final[OnboardingEffect] = "generate_credential"

# What a reset says the restarted run will do. ``undetermined`` is the honest
# answer for a run with no complete login pair: the route then depends on an
# operator's admission decision, which reset does not make on their behalf.
ExpectedRoute = Literal["login", "signup", "undetermined"]


class WorkflowStateStore(Protocol):
    """How a reset discards the durable workflow state of one run.

    A port rather than a call into the checkpointer, because "clear the workflow
    state" is the one destructive half of reset and it must be substitutable in a
    test that has no LangGraph checkpoint database. Defined here rather than
    imported: no module owns this verb yet, and reset is its only caller.
    """

    def clear_workflow_state(self, *, run_id: str, thread_id: str) -> bool:
        """Discard the run's checkpointed workflow state.

        POST: the run has no resumable workflow state. Returns ``True`` when state
              was actually discarded, ``False`` when there was none — both are
              successful resets, and neither touches the vault.
        """


@dataclass(frozen=True, slots=True)
class ResetOutcome:
    """What a reset did, and the four facts an operator needs to trust it.

    ``vault_references_preserved`` is the count of references that still resolve
    for the run's app slug and account binding *after* the reset, which is
    Property 13 made observable rather than asserted. ``committed`` is ``False``
    for a run whose current phase the table gives no route back to ``research``,
    and in that case nothing was written, nothing was cleared, and no session was
    released.
    """

    run_id: str
    accepted: bool
    phase: OnboardingPhase
    reason_code: OnboardingReasonCode
    committed: bool
    browser_session_released: bool
    workflow_state_cleared: bool
    vault_references_preserved: int
    expected_route_on_restart: ExpectedRoute


@dataclass(frozen=True, slots=True)
class RetryOutcome:
    """What a retry re-attempted, and what it refused to repeat.

    ``skipped_effects`` names every provider-visible effect the ledger proves
    already happened (Requirement 14.13). ``generation`` is the counter value the
    retry *reused*: it is the same number the failed attempt used, which is why
    the retry derives an operation key that is already reserved rather than a new
    one (Requirement 14.15).
    """

    run_id: str
    accepted: bool
    phase: OnboardingPhase
    attempt: int
    reason_code: OnboardingReasonCode
    committed: bool
    generation: int
    skipped_effects: tuple[OnboardingEffect, ...] = ()


class OnboardingRunRecoveryService(OnboardingRunControlService):
    """Reset and Retry Current Step for a run on the onboarding phase machine.

    A subclass rather than a sibling: reset and retry commit boundaries and
    project statuses exactly the way pause, resume, and cancel do, and duplicating
    that commit-then-project step would give the control surface two
    implementations that could disagree about how a refused status edge is
    handled. The five controls are one surface; this half is the two that put a
    run back to work.
    """

    def __init__(
        self,
        *,
        storage: OperationsStorage,
        phases: PhaseHistoryStore,
        effects: OnboardingEffectLedger,
        workflow: WorkflowStateStore | None = None,
        credentials: CredentialReferenceProbe | None = None,
        release_session: BrowserSessionRelease | None = None,
        probe: EffectOutcomeProbe | None = None,
    ) -> None:
        super().__init__(
            storage=storage,
            phases=phases,
            effects=effects,
            release_session=release_session,
            probe=probe,
        )
        self._workflow = workflow
        self._credentials = credentials

    # --- reset --------------------------------------------------------------

    def reset_run(self, run_id: str, *, confirm: bool) -> ResetOutcome:
        """Release the session, clear workflow state, and restart at ``research``.

        PRE:  ``confirm`` is ``True``. Anything else raises before a single side
              effect, so an unconfirmed reset releases no session and leaves the
              workflow state and every vault reference untouched
              (Requirement 14.12).
        POST: Q1. the bound browser session is released under the ``run_reset``
                  reason and the workflow state is cleared (Requirement 14.7).
              Q2. phase ``research`` is committed (Requirement 14.8), reached
                  through ``paused`` when the run was mid-flight.
              Q3. every vault reference for the run's app slug and account binding
                  still resolves, and the count of them is reported
                  (Requirements 14.9, 14.11). No delete is reachable from here.
              Q4. a run whose phase the table gives no route to ``research`` is
                  left entirely alone: nothing released, nothing cleared, nothing
                  committed.

        Q3 is the guarantee worth restating: the restarted run probes the same
        vault, finds the same pair, and routes to login with reason code
        ``credentials_present`` and zero operator prompts (Requirement 14.10) —
        which is the whole reason reset is safe to offer at all.
        """

        if confirm is not True:
            # Raised, not reported: an unconfirmed reset is a malformed request
            # rather than a refused one, and it must not reach the release port.
            raise ValueError("reset requires explicit confirmation")

        preserved, route = self._preserved_vault_state(run_id)
        boundary = self._last_boundary(run_id)
        path = None if boundary is None else self._reset_path(boundary.to_phase)
        if boundary is None or path is None:
            LOGGER.info(
                "onboarding run %s cannot be reset from phase %s",
                run_id,
                boundary.to_phase if boundary else None,
            )
            return ResetOutcome(
                run_id=run_id,
                accepted=False,
                phase=boundary.to_phase if boundary else INITIAL_PHASE,
                reason_code=PHASE_REPLAY_NOOP,
                committed=False,
                browser_session_released=False,
                workflow_state_cleared=False,
                vault_references_preserved=preserved,
                expected_route_on_restart=route,
            )

        released = False
        if self._release_session is not None:
            released = bool(self._release_session(run_id=run_id, reason=RESET_RELEASE_REASON))
        cleared = self._clear_workflow_state(run_id)
        committed = self._commit_reset_path(run_id, boundary=boundary, path=path)
        # Read again *after* the reset, so the count reports what survived rather
        # than what was there before — the only reading that proves Property 13.
        preserved, route = self._preserved_vault_state(run_id)
        LOGGER.info(
            "onboarding run %s reset (session released: %s, %d vault reference(s) preserved)",
            run_id,
            released,
            preserved,
        )
        return ResetOutcome(
            run_id=run_id,
            accepted=True,
            phase=INITIAL_PHASE if committed else boundary.to_phase,
            reason_code=RESET_REASON_CODE,
            committed=committed,
            browser_session_released=released,
            workflow_state_cleared=cleared,
            vault_references_preserved=preserved,
            expected_route_on_restart=route,
        )

    # --- retry current step -------------------------------------------------

    def retry_current_step(
        self,
        run_id: str,
        *,
        expected_phase: OnboardingPhase | None = None,
    ) -> RetryOutcome:
        """Re-attempt the phase the run is standing in, and nothing else.

        PRE:  ``expected_phase``, when given, equals the run's current phase. A
              mismatch is refused with :data:`PHASE_REPLAY_NOOP` and changes
              nothing, so an operator cannot retry a step the run has already left.
        POST: Q1. the run's current phase is re-entered with the attempt counter
                  advanced, and no other phase is touched (Requirement 14.13).
              Q2. every effect whose reservation reports completed is named in
                  ``skipped_effects`` and is not re-submitted (Requirement 14.13).
              Q3. the credential generation counter is unchanged, so the retry
                  derives the operation key already reserved for the step
                  (Requirement 14.15).
              Q4. a run holding an ``outcome_unknown`` reservation is refused with
                  that reason code and nothing is written: an ambiguous outcome
                  authorizes no submission at all.

        Only the attempt advances. That is what makes the retry a re-attempt of
        one step rather than a replay of the walk: the reservations, the profile
        digest, and the generation counter are all carried across unchanged.
        """

        boundary = self._last_boundary(run_id)
        if (
            boundary is None
            or boundary.to_phase in TERMINAL_PHASES
            or boundary.to_phase in WAITING_PHASES
        ):
            # A terminal run has no current step, and a waiting run re-enters
            # through resume — retrying it would skip the gate it stopped at.
            return self._refused_retry(
                run_id,
                phase=boundary.to_phase if boundary else INITIAL_PHASE,
                attempt=boundary.attempt if boundary else 0,
                reason_code=PHASE_REPLAY_NOOP,
            )
        phase = boundary.to_phase
        if expected_phase is not None and expected_phase != phase:
            return self._refused_retry(
                run_id, phase=phase, attempt=boundary.attempt, reason_code=PHASE_REPLAY_NOOP
            )

        reservations = self._effects.reservations(run_id=run_id)
        if any(record.disposition == UNKNOWN_DISPOSITION for record in reservations):
            return self._refused_retry(
                run_id, phase=phase, attempt=boundary.attempt, reason_code=OUTCOME_UNKNOWN
            )
        skipped = tuple(
            record.effect for record in reservations if record.disposition == COMPLETED_DISPOSITION
        )
        # The read that must never become ``next_generation``: this is the value
        # the failed attempt used, so the key it derives is already reserved.
        generation = self._phases.current_generation(run_id=run_id, effect=CREDENTIAL_EFFECT)
        attempt = boundary.attempt + 1
        committed = self._commit(
            run_id=run_id,
            boundary=boundary,
            to_phase=phase,
            reason_code=RETRY_REASON_CODE,
            attempt=attempt,
            event_type=RETRIED_EVENT,
        )
        LOGGER.info(
            "onboarding run %s retrying phase %s (attempt %d, %d effect(s) skipped)",
            run_id,
            phase,
            attempt,
            len(skipped),
        )
        return RetryOutcome(
            run_id=run_id,
            accepted=True,
            phase=phase,
            attempt=attempt if committed else boundary.attempt,
            reason_code=RETRY_REASON_CODE,
            committed=committed,
            generation=generation,
            skipped_effects=skipped,
        )

    # --- internals ----------------------------------------------------------

    def _refused_retry(
        self,
        run_id: str,
        *,
        phase: OnboardingPhase,
        attempt: int,
        reason_code: OnboardingReasonCode,
    ) -> RetryOutcome:
        """A retry that changed nothing, reporting why."""

        LOGGER.info("onboarding run %s retry refused: %s", run_id, reason_code)
        return RetryOutcome(
            run_id=run_id,
            accepted=False,
            phase=phase,
            attempt=attempt,
            reason_code=reason_code,
            committed=False,
            generation=0,
        )

    def _reset_path(self, phase: OnboardingPhase) -> tuple[OnboardingPhase, ...] | None:
        """The boundaries a reset must commit to get from ``phase`` to ``research``.

        Three answers, all read off the phase table rather than decided here: the
        identity restart for a run still in ``research``, the direct edge that
        only ``paused`` has, and the park-then-restart pair for a mid-flight run.
        ``None`` means the table admits neither, which today is ``vault_check``
        and the terminal phases.
        """

        if phase in TERMINAL_PHASES:
            return None
        if phase == INITIAL_PHASE or is_legal_phase_transition(phase, INITIAL_PHASE):
            return (INITIAL_PHASE,)
        if is_legal_phase_transition(phase, PAUSED_PHASE) and is_legal_phase_transition(
            PAUSED_PHASE, INITIAL_PHASE
        ):
            return (PAUSED_PHASE, INITIAL_PHASE)
        return None

    def _commit_reset_path(
        self,
        run_id: str,
        *,
        boundary: PhaseTransition,
        path: tuple[OnboardingPhase, ...],
    ) -> bool:
        """Commit each boundary on the reset path; report whether it reached research.

        Every step carries the same attempt bump, which counts the resets the run
        has already performed. Two resets of the same phase are therefore genuinely
        different boundaries, while a repeated *identical* reset request collides
        on the boundary constraint and is the no-op it should be. Each step re-reads
        the committed boundary rather than predicting it, so a crash between the
        two leaves a parked run a later reset can still finish.
        """

        bump = 1 + self._reset_count(run_id)
        current = boundary
        for target in path:
            committed = self._commit(
                run_id=run_id,
                boundary=current,
                to_phase=target,
                reason_code=RESET_REASON_CODE,
                attempt=current.attempt + bump,
                event_type=RESET_EVENT,
            )
            if not committed:
                return False
            current = self._last_boundary(run_id) or current
        return current.to_phase == INITIAL_PHASE

    def _reset_count(self, run_id: str) -> int:
        """How many resets the run has already completed."""

        return sum(
            1
            for boundary in self._phases.history(run_id=run_id)
            if boundary.to_phase == INITIAL_PHASE and boundary.reason_code == RESET_REASON_CODE
        )

    def _clear_workflow_state(self, run_id: str) -> bool:
        """Discard the run's checkpointed workflow state through the port."""

        if self._workflow is None:
            return False
        record = self._storage.get_run(run_id)
        thread_id = str((record or {}).get("thread_id") or run_id)
        return bool(self._workflow.clear_workflow_state(run_id=run_id, thread_id=thread_id))

    def _preserved_vault_state(self, run_id: str) -> tuple[int, ExpectedRoute]:
        """How many references the run's binding holds, and the route they imply.

        Two reference-only reads: the count includes a partial pair, because the
        promise is that reset destroys nothing, while the route is decided by
        :func:`ops.onboarding.admission.probe_login_refs` so this module cannot
        disagree with the admission path about what a partial pair means. Neither
        read can resolve a value — the probe's only method returns references.
        """

        record = self._storage.get_run(run_id)
        probe = self._credentials
        if probe is None or record is None:
            return 0, "undetermined"
        app_slug = str(record.get("app_slug") or "")
        account_ref = str(record.get("browser_account_ref") or "")
        if not app_slug or not account_ref:
            return 0, "undetermined"
        references = probe.account_login_references(app_slug=app_slug, account_ref=account_ref)
        preserved = sum(1 for reference in references.values() if reference)
        admission = probe_login_refs(probe, app_slug=app_slug, account_ref=account_ref)
        return preserved, ("login" if admission.credentials_present else "undetermined")


__all__ = [
    "COMPLETED_DISPOSITION",
    "CREDENTIAL_EFFECT",
    "RESET_EVENT",
    "RESET_REASON_CODE",
    "RESET_RELEASE_REASON",
    "RETRIED_EVENT",
    "RETRY_REASON_CODE",
    "UNKNOWN_DISPOSITION",
    "ExpectedRoute",
    "OnboardingRunRecoveryService",
    "ResetOutcome",
    "RetryOutcome",
    "RunReconciliationContext",
    "RunReconciliationService",
    "WorkflowStateStore",
]
